// Static Phase 1 security drift analysis data.
// All findings, verdicts, and compliance results are derived from the
// completed Phase 1 analysis and remediation of this repository.

export const REPO = {
  name: "security-drift-demo",
  branch: "main",
  baseline: "SECURITY_PATTERNS.md",
};

export const BASELINE = {
  file: "SECURITY_PATTERNS.md",
  totalRules: 20,
  satisfiedRules: 20,
  sections: [
    { name: "Password Security", rules: 3, satisfied: 3 },
    { name: "Authentication", rules: 3, satisfied: 3 },
    { name: "Error Handling", rules: 3, satisfied: 3 },
    { name: "Sensitive Data", rules: 3, satisfied: 3 },
    { name: "Security-Sensitive Randomness", rules: 2, satisfied: 2 },
    { name: "Password Reset", rules: 6, satisfied: 6 },
  ],
};

export const FINDINGS = [
  {
    id: "F-1",
    severity: "CRITICAL",
    status: "FIXED",
    title: "Weak reset token generation",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password — line 136",
    patternViolated: "Security-Sensitive Randomness",

    // A. The pattern already established elsewhere in the repository
    repositoryPattern:
      "SECURITY_PATTERNS.md §Security-Sensitive Randomness: \"Security-sensitive tokens must use a cryptographically secure random generator. Math.random() must not be used for authentication or password-reset tokens.\"",

    // B. What was actually found in the new implementation
    detectedImplementation:
      "Math.random().toString(36).substring(2, 15) — a non-cryptographic PRNG producing ~13 base-36 characters (~43 bits of biased entropy). The code contained its own comment: \"// INTENTIONALLY INSECURE\".",

    // C. Why this is drift (not just a general security issue)
    driftReason:
      "The repository baseline explicitly prohibits Math.random() for this exact use case. The new password-reset implementation violates a rule written specifically to govern reset token generation. This is a direct conflict with an established pattern, not a generic security concern.",

    verdict: "Intentional — self-documented in source code",

    before: {
      label: "Math.random() — non-cryptographic PRNG",
      code: "// INTENTIONALLY INSECURE:\n// Math.random() is not suitable for security-sensitive tokens.\nconst resetToken = Math.random().toString(36).substring(2, 15);",
      impact:
        "~43 bits of biased, predictable randomness. Token space brute-forceable; V8 PRNG state is observable under adversarial conditions.",
    },
    after: {
      label: "crypto.randomBytes(32) — 256-bit CSPRNG",
      code: "// F-1: Use a cryptographically secure random generator for the reset token.\nconst resetToken = crypto.randomBytes(32).toString(\"hex\");",
      property: "256 bits of OS-sourced entropy. 64-character hex token. Brute-force infeasible.",
    },
  },
  {
    id: "F-2",
    severity: "HIGH",
    status: "FIXED",
    title: "Reset token exposed in API response",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password — lines 145–148",
    patternViolated: "Sensitive Data",

    repositoryPattern:
      "SECURITY_PATTERNS.md §Sensitive Data: \"Sensitive tokens should be handled securely. Security-sensitive values should not be exposed unnecessarily.\" The JWT (the other credential issued by this codebase) is returned only as the direct product of a successful authenticated action — never as a side-channel.",

    detectedImplementation:
      "res.json({ message: \"Password reset token generated\", resetToken }) — the raw reset token is returned directly in the HTTP response body. No out-of-band delivery (e.g. email) was implemented.",

    driftReason:
      "The existing JWT issuance pattern demonstrates that credentials should not be gratuitously exposed in response bodies. The reset token receives different, weaker handling than the JWT despite serving an equivalent security role. The absence of an // INTENTIONALLY INSECURE comment (present in F-1) suggests the exposure was not deliberate.",

    verdict: "Potentially accidental — no justifying comment unlike F-1",

    before: {
      label: "Raw token returned in HTTP response body",
      code: "res.json({\n  message: \"Password reset token generated\",\n  resetToken\n});",
      impact:
        "Token visible in any HTTP response log, proxy, or XSS leak. Out-of-band delivery (email) is bypassed entirely.",
    },
    after: {
      label: "Token logged server-side only; response is generic",
      code: "// F-2: Do not return the reset token in the HTTP response.\n// In production this would be sent via email.\nconsole.log(`[PASSWORD RESET] Token for ${email}: ${resetToken}`);\n\nres.json({\n  message: \"If that email is registered, a password reset token has been sent\"\n});",
      property:
        "HTTP response body contains only a generic message. Token is not visible to an HTTP observer. console.log stub marks the wiring point for email delivery.",
    },
  },
  {
    id: "F-3",
    severity: "HIGH",
    status: "FIXED",
    title: "Account enumeration in password reset",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password — lines 128–131",
    patternViolated: "Password Reset — anti-enumeration",

    repositoryPattern:
      "Login endpoint returns HTTP 401 with \"Invalid email or password\" for both user-not-found and wrong-password — a deliberate, unified response to prevent account enumeration. SECURITY_PATTERNS.md §Password Reset explicitly requires: \"Password reset responses should avoid revealing whether an account exists.\"",

    detectedImplementation:
      "if (!user) { return res.status(404).json({ message: \"User not found\" }); } — a distinct HTTP 404 with a message that directly confirms the account does not exist.",

    driftReason:
      "The login endpoint (the reference flow) explicitly applies anti-enumeration. The forgot-password endpoint applies a different pattern — a 404 with a disclosing message — despite the rule being explicitly extended to reset flows in the documented baseline. The inconsistency is between two related endpoints in the same file.",

    verdict: "Potentially accidental — directly contradicts a named rule in §Password Reset",

    before: {
      label: "HTTP 404 reveals account non-existence",
      code: "const user = await User.findOne({ email });\n\nif (!user) {\n  return res.status(404).json({\n    message: \"User not found\"\n  });\n}",
      impact:
        "Attacker can enumerate registered email addresses by comparing 404 (unregistered) vs 200 (registered) responses.",
    },
    after: {
      label: "Identical 200 response regardless of account existence",
      code: "// F-3: Always return a neutral response regardless of whether the account exists.\n// This prevents account enumeration via the reset flow.\nif (!user) {\n  return res.json({\n    message: \"If that email is registered, a password reset token has been sent\"\n  });\n}",
      property:
        "Both found and not-found paths return HTTP 200 with identical JSON. Consistent with the login endpoint pattern.",
    },
  },
  {
    id: "F-4",
    severity: "MEDIUM",
    status: "FIXED",
    title: "Plaintext reset token stored in database",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password (store) + POST /reset-password (compare)",
    patternViolated: "Sensitive Data — credential storage",

    repositoryPattern:
      "Passwords are stored as bcrypt hashes and verified with bcrypt.compare() — a constant-time, at-rest-protected comparison. SECURITY_PATTERNS.md §Password Security: \"Passwords must never be stored in plaintext. Password verification must use bcrypt comparison.\" The reset token functions as a credential granting equivalent account access.",

    detectedImplementation:
      "user.resetToken = resetToken (raw string written to MongoDB). Reset validation via User.findOne({ email, resetToken }) — plaintext equality match. No hashing, no constant-time comparison.",

    driftReason:
      "Passwords (credentials) are hashed before storage; the reset token (an equivalent credential) is stored in plaintext. Both are in the same file, handled by the same developer. The asymmetry is not documented or commented, contrasting with F-1 which carries an explicit rationale comment.",

    verdict: "Potentially accidental — asymmetric treatment of equivalent credentials in the same file",

    before: {
      label: "Plaintext token stored in MongoDB; plaintext DB lookup",
      code: "// Stored as raw string:\nuser.resetToken = resetToken;\n\n// Compared by plaintext DB equality:\nconst user = await User.findOne({\n  email,\n  resetToken\n});",
      impact:
        "A DB backup, query log, or injection vulnerability exposes all active reset tokens directly. Passwords in the same breach remain bcrypt-protected.",
    },
    after: {
      label: "SHA-256 hash stored; hash compared on reset",
      code: "// F-4: Store only the SHA-256 hash of the token.\nconst resetTokenHash = crypto\n  .createHash(\"sha256\")\n  .update(resetToken)\n  .digest(\"hex\");\nuser.resetToken = resetTokenHash;\n\n// Compare hashes, not plaintext:\nconst user = await User.findOne({\n  email,\n  resetToken: resetTokenHash\n});",
      property:
        "DB stores only SHA-256 digests of one-time 256-bit tokens. Plaintext is never persisted. A DB read compromise cannot recover the original token.",
    },
  },
];

export const EXCLUDED_FINDINGS = [
  {
    id: "F-5",
    title: "No rate limiting on authentication endpoints",
    category: "GENERAL GAP",
    categoryStyle: "gap",
    explanation:
      "Rate limiting is absent from every endpoint uniformly — login, register, forgot-password, reset-password, and profile. Because the gap is consistent across all flows, there is no conflicting pattern established elsewhere in the repository. This is a missing control, not a deviation from an established pattern.",
  },
  {
    id: "F-6",
    title: "Register endpoint discloses email already in use (HTTP 409)",
    category: "INTENTIONAL DESIGN",
    categoryStyle: "intentional",
    explanation:
      "Returning 409 \"User already exists\" during registration is a deliberate, conventional UX trade-off. SECURITY_PATTERNS.md §Error Handling explicitly scopes the anti-enumeration rule to login only, not registration. The behavior is consistent with the documented baseline.",
  },
  {
    id: "F-7",
    title: "Integration test asserts reset token in response body",
    category: "TEST ARTIFACT",
    categoryStyle: "artifact",
    explanation:
      "The test was written to exercise the then-current implementation. It is a derivative of F-2 (token in response), not an independent drift finding. Its security impact is fully captured under F-2. The test was updated as part of the F-2 remediation.",
  },
];

export const VERIFICATION = {
  confirmedFindings: 4,
  remediatedFindings: 4,
  remainingDrift: 0,
  baselineRulesSatisfied: 20,
  baselineRulesTotal: 20,
  testSuites: 3,
  testsPassing: 3,
  testsFailing: 0,
};

export const ANALYSIS_TIMELINE = [
  {
    stage: "Scan",
    label: "Scan",
    value: 7,
    unit: "potential deviations",
    detail: "All password-reset and auth routes scanned against SECURITY_PATTERNS.md",
  },
  {
    stage: "Validation",
    label: "Validate",
    value: 4,
    unit: "confirmed security drifts",
    detail: "Each deviation checked: genuine drift vs intentional design vs general gap",
  },
  {
    stage: "Remediation",
    label: "Remediate",
    value: 4,
    unit: "fixes applied",
    detail: "Minimal targeted changes — crypto PRNG, token hashing, response hardening",
  },
  {
    stage: "Verification",
    label: "Verify",
    value: 0,
    unit: "confirmed drift remaining",
    detail: "20/20 baseline rules satisfied · 3/3 test suites passing",
  },
];

export const WORKFLOW_STEPS = [
  {
    step: 1,
    label: "Detect",
    description: "Scan repository for deviations from established security patterns",
  },
  {
    step: 2,
    label: "Validate",
    description: "Confirm each finding is genuine drift, not intentional design or a false positive",
  },
  {
    step: 3,
    label: "Remediate",
    description: "Apply minimal, targeted fixes that restore the security baseline",
  },
  {
    step: 4,
    label: "Verify",
    description: "Re-run analysis and tests to confirm full baseline compliance",
  },
];
