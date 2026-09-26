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
    before: {
      label: "Math.random() — non-cryptographic PRNG",
      code: "const resetToken = Math.random().toString(36).substring(2, 15);",
      impact:
        "~43 bits of biased, predictable randomness. Token space brute-forceable; V8 PRNG state is observable.",
    },
    after: {
      label: "crypto.randomBytes(32) — 256-bit CSPRNG",
      code: 'const resetToken = crypto.randomBytes(32).toString("hex");',
      property: "256 bits of OS-sourced entropy. Brute-force infeasible.",
    },
    verdict: "Intentional — self-documented",
  },
  {
    id: "F-2",
    severity: "HIGH",
    status: "FIXED",
    title: "Reset token exposed in API response",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password — lines 145–148",
    patternViolated: "Sensitive Data",
    before: {
      label: "Raw token returned in HTTP response body",
      code: 'res.json({ message: "Password reset token generated", resetToken });',
      impact:
        "Token visible in any HTTP response log, proxy, or XSS leak. Out-of-band delivery bypassed entirely.",
    },
    after: {
      label: "Token delivered out-of-band; response is generic",
      code: 'console.log(`[PASSWORD RESET] Token for ${email}: ${resetToken}`);\nres.json({ message: "If that email is registered, a password reset token has been sent" });',
      property:
        "HTTP response body contains only a generic message. Token is not visible to an HTTP observer.",
    },
    verdict: "Potentially accidental",
  },
  {
    id: "F-3",
    severity: "HIGH",
    status: "FIXED",
    title: "Account enumeration in password reset",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password — lines 128–131",
    patternViolated: "Password Reset — anti-enumeration",
    before: {
      label: "HTTP 404 reveals whether the email is registered",
      code: 'if (!user) {\n  return res.status(404).json({ message: "User not found" });\n}',
      impact:
        "Attacker can enumerate all registered email addresses by observing 404 vs 200 responses.",
    },
    after: {
      label: "Identical 200 response for both found and not-found paths",
      code: 'if (!user) {\n  return res.json({ message: "If that email is registered, a password reset token has been sent" });\n}',
      property:
        "Account enumeration via forgot-password is closed. Consistent with the login endpoint pattern.",
    },
    verdict: "Potentially accidental",
  },
  {
    id: "F-4",
    severity: "MEDIUM",
    status: "FIXED",
    title: "Plaintext reset token stored in database",
    file: "backend/routes/authRoutes.js",
    location: "POST /forgot-password (store) + POST /reset-password (compare)",
    patternViolated: "Sensitive Data — credential storage",
    before: {
      label: "Raw token written to MongoDB; plaintext DB lookup",
      code: "user.resetToken = resetToken;\n// ...\nconst user = await User.findOne({ email, resetToken });",
      impact:
        "DB backup or injection compromise exposes all active reset tokens directly. Passwords in the same breach remain bcrypt-protected.",
    },
    after: {
      label: "SHA-256 hash stored; submitted token hashed before lookup",
      code: 'const hash = crypto.createHash("sha256").update(resetToken).digest("hex");\nuser.resetToken = hash;\n// ...\nconst user = await User.findOne({ email, resetToken: hash });',
      property:
        "DB stores only SHA-256 digests of one-time 256-bit tokens. Plaintext is never persisted.",
    },
    verdict: "Potentially accidental",
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
  outOfScopeFindings: [
    { id: "F-5", reason: "General gap — uniform absence of rate limiting, not inter-flow drift" },
    { id: "F-6", reason: "Intentional design — register 409 is a documented UX trade-off" },
  ],
};

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
