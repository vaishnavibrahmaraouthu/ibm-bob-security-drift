/**
 * findingClassifier.js
 *
 * Applies the four-class classification decision tree to each RawCandidate
 * produced by driftDetector and returns structured Finding objects.
 *
 * Decision order:
 *   1. TEST ARTIFACT   — file is a test file
 *   2. INTENTIONAL DESIGN — deviation has an intentional-comment marker
 *   3. GENERAL GAP     — no established pattern exists anywhere in the repo
 *   4. CONFIRMED DRIFT — established pattern exists AND code deviates from it
 *
 * The shape of a Finding is designed to be compatible with the existing
 * frontend FindingCard model (findings.js).
 */

"use strict";

const { DETECTOR } = require("./driftDetector");

// ─── Classification labels ────────────────────────────────────────────────────

const CATEGORY = {
  CONFIRMED_DRIFT:    "CONFIRMED_DRIFT",
  GENERAL_GAP:        "GENERAL_GAP",
  INTENTIONAL_DESIGN: "INTENTIONAL_DESIGN",
  TEST_ARTIFACT:      "TEST_ARTIFACT",
};

// ─── Static finding metadata ─────────────────────────────────────────────────
// Each detector ID maps to the full context needed to build a rich Finding.
// This metadata is authoritative for the Phase 1 pattern space.

const DETECTOR_META = {
  [DETECTOR.INSECURE_RANDOM]: {
    title:     "Insecure token generation — Math.random() instead of crypto.randomBytes()",
    severity:  "CRITICAL",
    patternViolated: "Security-Sensitive Randomness",
    repositoryPattern:
      "SECURITY_PATTERNS.md §Security-Sensitive Randomness: " +
      '"Security-sensitive tokens must use a cryptographically secure random generator. ' +
      'Math.random() must not be used for authentication or password-reset tokens." ' +
      "The established implementation in this repository uses crypto.randomBytes(32).",
    driftReason:
      "The repository's documented baseline explicitly prohibits Math.random() for " +
      "security-sensitive tokens. The new implementation uses the prohibited PRNG for " +
      "a token that grants account access, directly contradicting the established " +
      "pattern in the same codebase.",
    before: {
      label:  "Math.random() — non-cryptographic PRNG",
      impact: "~43 bits of biased, predictable entropy. Token space is brute-forceable; V8 PRNG state is observable under adversarial conditions.",
    },
    after: {
      label:    "crypto.randomBytes(32) — 256-bit CSPRNG",
      property: "256 bits of OS-sourced entropy. 64-character hex token. Brute-force infeasible.",
      code:     'const resetToken = crypto.randomBytes(32).toString("hex");',
    },
    remediation: 'Replace Math.random() with crypto.randomBytes(32).toString("hex") and require("crypto") at the top of the file.',
  },

  [DETECTOR.TOKEN_IN_RESPONSE]: {
    title:     "Reset token exposed in HTTP response body",
    severity:  "HIGH",
    patternViolated: "Sensitive Data",
    repositoryPattern:
      "SECURITY_PATTERNS.md §Sensitive Data: " +
      '"Sensitive tokens should be handled securely. Security-sensitive values should not ' +
      'be exposed unnecessarily." The JWT (the other credential issued by this codebase) ' +
      "is returned only as the direct product of a successful authenticated action.",
    driftReason:
      "The existing JWT issuance pattern demonstrates that credentials should not be " +
      "gratuitously exposed in response bodies. The reset token receives weaker handling " +
      "than the JWT despite serving an equivalent security role. The absence of an " +
      "intentional-comment (unlike F-1) suggests the exposure was not deliberate.",
    before: {
      label:  "Raw token returned in HTTP response body",
      impact: "Token visible in any HTTP response log, proxy, or XSS leak. Out-of-band delivery (e.g. email) is bypassed entirely.",
    },
    after: {
      label:    "Token handled out-of-band; response is generic",
      property: "HTTP response body contains only a generic message. Token is not visible to an HTTP observer.",
      code:     'console.log(`[PASSWORD RESET] Token for ${email}: ${resetToken}`);\nres.json({ message: "If that email is registered, a password reset token has been sent" });',
    },
    remediation: "Remove resetToken from the res.json() call. Log or email the token server-side only and return a generic message.",
  },

  [DETECTOR.ACCOUNT_ENUMERATION]: {
    title:     "Account enumeration in password-reset flow",
    severity:  "HIGH",
    patternViolated: "Password Reset — anti-enumeration",
    repositoryPattern:
      'Login endpoint returns HTTP 401 with "Invalid email or password" for both ' +
      "user-not-found and wrong-password — a deliberate, unified response to prevent " +
      "account enumeration. SECURITY_PATTERNS.md §Password Reset explicitly requires: " +
      '"Password reset responses should avoid revealing whether an account exists."',
    driftReason:
      "The login endpoint (the reference flow) explicitly applies anti-enumeration. " +
      "The forgot-password endpoint applies a different pattern — a 404 with a " +
      "disclosing message — despite the rule being explicitly extended to reset flows " +
      "in the documented baseline.",
    before: {
      label:  "HTTP 404 reveals account non-existence",
      impact: "Attacker can enumerate registered email addresses by comparing 404 (unregistered) vs 200 (registered) responses.",
    },
    after: {
      label:    "Identical 200 response regardless of account existence",
      property: 'Both found and not-found paths return HTTP 200 with identical JSON. Consistent with the login endpoint pattern.',
      code:     'if (!user) {\n  return res.json({ message: "If that email is registered, a password reset token has been sent" });\n}',
    },
    remediation: 'Replace the 404/revealing response with a neutral 200 and a generic message such as "If that email is registered, a password reset token has been sent".',
  },

  [DETECTOR.PLAINTEXT_TOKEN_STORE]: {
    title:     "Plaintext reset token stored in database",
    severity:  "MEDIUM",
    patternViolated: "Sensitive Data — credential storage",
    repositoryPattern:
      "Passwords are stored as bcrypt hashes and verified with bcrypt.compare() — " +
      "a constant-time, at-rest-protected comparison. SECURITY_PATTERNS.md §Password Security: " +
      '"Passwords must never be stored in plaintext." The reset token functions as a ' +
      "credential granting equivalent account access.",
    driftReason:
      "Passwords (credentials) are hashed before storage; the reset token (an equivalent " +
      "credential) is stored in plaintext. Both are in the same file, handled by the same " +
      "developer. The asymmetry is not documented or commented, contrasting with F-1 which " +
      "carries an explicit rationale comment.",
    before: {
      label:  "Plaintext token stored in MongoDB; plaintext DB lookup",
      impact: "A DB backup, query log, or injection vulnerability exposes all active reset tokens directly. Passwords in the same breach remain bcrypt-protected.",
    },
    after: {
      label:    "SHA-256 hash stored; hash compared on reset",
      property: "DB stores only SHA-256 digests of one-time 256-bit tokens. Plaintext is never persisted.",
      code:     'const resetTokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");\nuser.resetToken = resetTokenHash;',
    },
    remediation: "Store crypto.createHash('sha256').update(resetToken).digest('hex') instead of the raw token. Compare hashes on reset.",
  },
};

// ─── Severity ordering (for sorting) ─────────────────────────────────────────

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// ─── Classifier ───────────────────────────────────────────────────────────────

let _findingCounter = 0;

/**
 * Classify a single RawCandidate and return a structured Finding.
 *
 * @param {import('./driftDetector').RawCandidate} candidate
 * @param {number} index - Used to generate a stable ID for this run.
 * @returns {Finding}
 */
function classifyCandidate(candidate, index) {
  const meta = DETECTOR_META[candidate.detectorId] || {};

  // Decision tree ─────────────────────────────────────────────────────────
  let classification;

  if (candidate.isTestFile) {
    classification = CATEGORY.TEST_ARTIFACT;
  } else if (candidate.intentionalCommentPresent) {
    classification = CATEGORY.INTENTIONAL_DESIGN;
  } else if (!candidate.establishedPatternExists) {
    classification = CATEGORY.GENERAL_GAP;
  } else {
    classification = CATEGORY.CONFIRMED_DRIFT;
  }

  // Build the Finding ──────────────────────────────────────────────────────
  const id = `F-${index + 1}`;

  /** @type {Finding} */
  const finding = {
    id,
    detectorId:   candidate.detectorId,
    category:     classification,
    severity:     meta.severity || "INFO",
    status:       classification === CATEGORY.CONFIRMED_DRIFT ? "OPEN" : "EXCLUDED",
    title:        meta.title || `Deviation detected by ${candidate.detectorId}`,
    file:         candidate.file,
    line:         candidate.line,

    // Investigation fields (matches FindingCard model)
    patternViolated:        meta.patternViolated || "",
    repositoryPattern:      meta.repositoryPattern || "",
    detectedImplementation: candidate.matchedText,
    surroundingCode:        candidate.surroundingCode,
    driftReason:            classification === CATEGORY.CONFIRMED_DRIFT ? (meta.driftReason || "") : "",

    // Classification explanation
    classificationReason: _classificationReason(classification, candidate),

    // Before / after (populated for confirmed drift and intentional design)
    before: meta.before
      ? { ...meta.before, code: candidate.surroundingCode }
      : null,
    after:  meta.after || null,

    // Remediation guidance (only meaningful for confirmed drift)
    remediation: classification === CATEGORY.CONFIRMED_DRIFT ? (meta.remediation || "") : "",

    // Verification placeholder — populated after remediation
    verification: null,
  };

  return finding;
}

/**
 * Produce a human-readable sentence explaining why this classification was chosen.
 *
 * @param {string} classification
 * @param {import('./driftDetector').RawCandidate} candidate
 * @returns {string}
 */
function _classificationReason(classification, candidate) {
  switch (classification) {
    case CATEGORY.TEST_ARTIFACT:
      return `Located in a test file (${candidate.file}). Security impact captured by the production-code finding for this deviation.`;
    case CATEGORY.INTENTIONAL_DESIGN:
      return "An intentional-comment marker (e.g. INTENTIONALLY INSECURE) is present near this deviation, indicating the developer made a deliberate choice.";
    case CATEGORY.GENERAL_GAP:
      return "No established pattern for this security concern was found anywhere else in the repository. Cannot be security drift if the pattern was never established.";
    case CATEGORY.CONFIRMED_DRIFT:
      return "An established pattern exists elsewhere in the repository. This code handles the same security concern differently, with no documented exception.";
    default:
      return "";
  }
}

// ─── Deduplication ────────────────────────────────────────────────────────────

/**
 * Remove duplicate findings: if the same detector + file + line appears more
 * than once (possible when multiple regex matches overlap), keep only the first.
 *
 * @param {RawCandidate[]} candidates
 * @returns {RawCandidate[]}
 */
function deduplicate(candidates) {
  const seen = new Set();
  return candidates.filter((c) => {
    const key = `${c.detectorId}::${c.file}::${c.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * @typedef {Object} Finding
 * @property {string}  id
 * @property {string}  detectorId
 * @property {string}  category          - One of CATEGORY.*
 * @property {string}  severity
 * @property {string}  status            - "OPEN" | "EXCLUDED"
 * @property {string}  title
 * @property {string}  file
 * @property {number}  line
 * @property {string}  patternViolated
 * @property {string}  repositoryPattern
 * @property {string}  detectedImplementation
 * @property {string}  surroundingCode
 * @property {string}  driftReason
 * @property {string}  classificationReason
 * @property {object|null} before
 * @property {object|null} after
 * @property {string}  remediation
 * @property {object|null} verification
 */

/**
 * @typedef {Object} AnalysisResult
 * @property {Finding[]} findings          - All findings (drift + excluded)
 * @property {Finding[]} confirmedDrift    - CONFIRMED_DRIFT only
 * @property {Finding[]} excluded          - Non-drift findings
 * @property {object}    summary
 * @property {number}    summary.potentialDeviations
 * @property {number}    summary.confirmedDrift
 * @property {number}    summary.excluded
 * @property {number}    summary.remainingDrift
 */

/**
 * Classify all raw candidates and return a structured AnalysisResult.
 *
 * @param {import('./driftDetector').RawCandidate[]} candidates
 * @returns {AnalysisResult}
 */
function classifyAll(candidates) {
  const deduped   = deduplicate(candidates);
  const findings  = deduped
    .map((c, i) => classifyCandidate(c, i))
    .sort((a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
    );

  const confirmedDrift = findings.filter((f) => f.category === CATEGORY.CONFIRMED_DRIFT);
  const excluded       = findings.filter((f) => f.category !== CATEGORY.CONFIRMED_DRIFT);

  return {
    findings,
    confirmedDrift,
    excluded,
    summary: {
      potentialDeviations: findings.length,
      confirmedDrift:      confirmedDrift.length,
      excluded:            excluded.length,
      remainingDrift:      confirmedDrift.filter((f) => f.status === "OPEN").length,
    },
  };
}

module.exports = { classifyAll, CATEGORY, DETECTOR_META };
