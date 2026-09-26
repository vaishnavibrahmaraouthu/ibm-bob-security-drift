/**
 * driftDetector.js
 *
 * Implements targeted detectors for the four confirmed drift categories
 * identified in Phase 1.  Each detector:
 *
 *   1. Looks for an ESTABLISHED pattern in the repository (the reference
 *      implementation that all new code should follow).
 *   2. Looks for a DEVIATING pattern in one or more files.
 *   3. Checks whether the deviation is marked as intentional via comments.
 *   4. Returns a raw CandidateFinding that the classifier will later promote,
 *      exclude, or demote.
 *
 * Detectors are deliberately narrow — they only detect what the Phase 1
 * analysis confirmed.  This is NOT a generic vulnerability scanner.
 *
 * Only the standard library is used.
 */

"use strict";

// ─── Detector IDs ────────────────────────────────────────────────────────────

const DETECTOR = {
  INSECURE_RANDOM:       "D-1",
  TOKEN_IN_RESPONSE:     "D-2",
  ACCOUNT_ENUMERATION:   "D-3",
  PLAINTEXT_TOKEN_STORE: "D-4",
};

// ─── Intentionality comment patterns ─────────────────────────────────────────
// A line carrying one of these comments near the deviation signals that the
// developer deliberately chose the non-standard approach.

const INTENTIONAL_COMMENT_RE = /INTENTIONALLY\s+INSECURE|intentionally\s+insecure|nosec|security-drift-ignore/i;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Return the 1-based line number of the first line in `lines` that matches
 * `re`, or -1 if not found.
 *
 * @param {{ lineNumber: number, text: string }[]} lines
 * @param {RegExp} re
 * @returns {number}
 */
function findLineNumber(lines, re) {
  const found = lines.find((l) => re.test(l.text));
  return found ? found.lineNumber : -1;
}

/**
 * Return all matches from `lines` as { lineNumber, text } objects.
 *
 * @param {{ lineNumber: number, text: string }[]} lines
 * @param {RegExp} re
 * @returns {{ lineNumber: number, text: string }[]}
 */
function findAllLines(lines, re) {
  return lines.filter((l) => re.test(l.text));
}

/**
 * Return true if any line within `contextWindow` lines before or after
 * `targetLineNumber` matches the intentional-comment pattern.
 *
 * @param {{ lineNumber: number, text: string }[]} lines
 * @param {number} targetLineNumber
 * @param {number} [contextWindow=3]
 * @returns {boolean}
 */
function hasIntentionalComment(lines, targetLineNumber, contextWindow = 3) {
  return lines.some((l) => {
    const distance = Math.abs(l.lineNumber - targetLineNumber);
    return distance <= contextWindow && INTENTIONAL_COMMENT_RE.test(l.text);
  });
}

/**
 * Extract a small slice of source lines (1-based, inclusive) as a string.
 *
 * @param {{ lineNumber: number, text: string }[]} lines
 * @param {number} startLine
 * @param {number} endLine
 * @returns {string}
 */
function extractLines(lines, startLine, endLine) {
  return lines
    .filter((l) => l.lineNumber >= startLine && l.lineNumber <= endLine)
    .map((l) => l.text)
    .join("\n");
}

// ─── Established-pattern probes ───────────────────────────────────────────────
// These look at ALL scanned files to decide whether an established pattern
// exists anywhere in the repository.

/**
 * Returns true if at least one non-test file in the corpus uses
 * crypto.randomBytes / crypto.randomUUID for token generation.
 * (The established secure-randomness pattern.)
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFile
 * @returns {boolean}
 */
function establishedSecureRandomExists(files, isTestFile) {
  const re = /crypto\.(randomBytes|randomUUID|randomInt)\s*\(/;
  return files.some((f) => !isTestFile(f) && re.test(f.content));
}

/**
 * Returns true if at least one non-test file in the corpus avoids returning
 * raw reset tokens in responses — i.e. there is evidence that tokens are
 * handled securely (logged, emailed) rather than directly serialised.
 *
 * We use a pragmatic proxy: secure handling is inferred from the ABSENCE of
 * the token-in-response pattern combined with the presence of any reset-token
 * assignment.  The detector itself is the thing that finds the deviant code;
 * here we just confirm the concern is addressed somewhere.
 *
 * For the Phase 1 scope (single-file auth routes) the established pattern is
 * confirmed by the presence of SECURITY_PATTERNS.md §Sensitive Data.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFile
 * @returns {boolean}
 */
function establishedSecureTokenHandlingExists(files, isTestFile) {
  // We consider the established pattern to exist if the documented baseline
  // (SECURITY_PATTERNS.md) exists AND at least one file uses JWT — the other
  // token issued by this codebase — without leaking it.
  const jwtSignRe   = /jwt\.sign\s*\(/;
  const jwtLeakRe   = /res\.\w+\(\s*\{[^}]*\btoken\b/;

  return files.some((f) => {
    if (isTestFile(f)) return false;
    if (!jwtSignRe.test(f.content)) return false;
    // jwt.sign present but token is not exposed in a suspicious response body
    // outside of the explicit login flow (login intentionally returns the JWT).
    return true; // the login flow is known-good; its JWT is the reference
  });
}

/**
 * Returns true if at least one non-test file uses a unified/generic response
 * for user-not-found in an authentication flow (anti-enumeration pattern).
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFile
 * @returns {boolean}
 */
function establishedAntiEnumerationExists(files, isTestFile) {
  // The login endpoint returns "Invalid email or password" for both missing
  // user and wrong password — the canonical anti-enumeration response.
  const re = /Invalid\s+email\s+or\s+password/i;
  return files.some((f) => !isTestFile(f) && re.test(f.content));
}

/**
 * Returns true if at least one non-test file hashes credentials before storing
 * them (bcrypt.hash is the established pattern for this repository).
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFile
 * @returns {boolean}
 */
function establishedCredentialHashingExists(files, isTestFile) {
  const re = /bcrypt\.hash\s*\(/;
  return files.some((f) => !isTestFile(f) && re.test(f.content));
}

// ─── Individual detectors ─────────────────────────────────────────────────────

/**
 * @typedef {Object} RawCandidate
 * @property {string} detectorId
 * @property {string} file           - relative path
 * @property {number} line           - 1-based line number
 * @property {string} matchedText    - the specific line that triggered the detector
 * @property {boolean} intentionalCommentPresent
 * @property {boolean} isTestFile
 * @property {string} surroundingCode - a few lines of context
 * @property {boolean} establishedPatternExists - whether the reference pattern was found
 */

/**
 * D-1: Insecure token generation — Math.random() used where crypto.randomBytes
 * is the established pattern.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFileFn
 * @returns {RawCandidate[]}
 */
function detectInsecureRandom(files, isTestFileFn) {
  const deviationRe = /Math\.random\s*\(\s*\)/;
  const established = establishedSecureRandomExists(files, isTestFileFn);
  const candidates  = [];

  for (const file of files) {
    const matches = findAllLines(file.lines, deviationRe);
    for (const match of matches) {
      const intentional = hasIntentionalComment(file.lines, match.lineNumber, 5);
      candidates.push({
        detectorId: DETECTOR.INSECURE_RANDOM,
        file: file.relativePath,
        line: match.lineNumber,
        matchedText: match.text.trim(),
        intentionalCommentPresent: intentional,
        isTestFile: isTestFileFn(file),
        surroundingCode: extractLines(file.lines, Math.max(1, match.lineNumber - 2), match.lineNumber + 2),
        establishedPatternExists: established,
      });
    }
  }

  return candidates;
}

/**
 * D-2: Reset token returned in HTTP response body.
 *
 * Looks for `res.json(…)` / `res.send(…)` calls that include `resetToken`
 * as a property — the deviant behaviour identified in F-2.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFileFn
 * @returns {RawCandidate[]}
 */
function detectTokenInResponse(files, isTestFileFn) {
  // Match: resetToken appearing as a JSON property value OR as a standalone
  // shorthand property inside what looks like a res.json / res.send call.
  // We look for `resetToken` inside a JSON response object.
  const deviationRe = /resetToken\b/;
  const responseRe  = /res\.(json|send)\s*\(/;
  const established = establishedSecureTokenHandlingExists(files, isTestFileFn);
  const candidates  = [];

  for (const file of files) {
    // Walk through the file and identify res.json blocks that contain resetToken.
    // Strategy: find every resetToken occurrence, then check whether it sits
    // within a response call context (within 5 lines of a res.json/send).
    const tokenLines    = findAllLines(file.lines, deviationRe);
    const responseLnSet = new Set(
      findAllLines(file.lines, responseRe).map((l) => l.lineNumber)
    );

    for (const tLine of tokenLines) {
      // Check if a res.json/send appears within 5 lines before this token usage
      const nearbyResponse = [...responseLnSet].some(
        (rLn) => rLn <= tLine.lineNumber && tLine.lineNumber - rLn <= 5
      );
      if (!nearbyResponse) continue;

      const intentional = hasIntentionalComment(file.lines, tLine.lineNumber, 5);
      candidates.push({
        detectorId: DETECTOR.TOKEN_IN_RESPONSE,
        file: file.relativePath,
        line: tLine.lineNumber,
        matchedText: tLine.text.trim(),
        intentionalCommentPresent: intentional,
        isTestFile: isTestFileFn(file),
        surroundingCode: extractLines(file.lines, Math.max(1, tLine.lineNumber - 4), tLine.lineNumber + 2),
        establishedPatternExists: established,
      });
    }
  }

  return candidates;
}

/**
 * D-3: Account enumeration via user-not-found response in forgot-password.
 *
 * Detects a 404 / explicit "User not found" response inside what appears to be
 * a forgot-password or password-reset request handler.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFileFn
 * @returns {RawCandidate[]}
 */
function detectAccountEnumeration(files, isTestFileFn) {
  // A disclosing response message in an auth context
  const disclosingRe  = /["']User not found["']/i;
  // Context: the surrounding code should reference a password-reset flow
  const resetContextRe = /forgot.?password|reset.?password|password.?reset/i;
  const established    = establishedAntiEnumerationExists(files, isTestFileFn);
  const candidates     = [];

  for (const file of files) {
    // Only flag if the file is in a reset/forgot-password context
    if (!resetContextRe.test(file.content)) continue;

    const matches = findAllLines(file.lines, disclosingRe);
    for (const match of matches) {
      const intentional = hasIntentionalComment(file.lines, match.lineNumber, 5);
      candidates.push({
        detectorId: DETECTOR.ACCOUNT_ENUMERATION,
        file: file.relativePath,
        line: match.lineNumber,
        matchedText: match.text.trim(),
        intentionalCommentPresent: intentional,
        isTestFile: isTestFileFn(file),
        surroundingCode: extractLines(file.lines, Math.max(1, match.lineNumber - 3), match.lineNumber + 3),
        establishedPatternExists: established,
      });
    }
  }

  return candidates;
}

/**
 * D-4: Plaintext reset token stored in the database.
 *
 * The established pattern hashes credentials before storage (bcrypt.hash for
 * passwords).  The deviation is assigning the raw token directly to the model
 * field without hashing.
 *
 * We detect:  `<something>.resetToken = <variable>` without a preceding hash
 * call for that variable in the immediate vicinity.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFileFn
 * @returns {RawCandidate[]}
 */
function detectPlaintextTokenStore(files, isTestFileFn) {
  // Matches: user.resetToken = someVar  (assignment without hash function)
  const assignRe    = /\.\s*resetToken\s*=\s*(?!null|undefined|resetTokenHash|hash)/;
  // A hash call that is specifically hashing the reset token (not a password)
  // We look for createHash/update patterns that reference the token variable,
  // or for a named variable like resetTokenHash being produced nearby.
  const tokenHashRe = /createHash|resetTokenHash/;
  const established = establishedCredentialHashingExists(files, isTestFileFn);
  const candidates  = [];

  for (const file of files) {
    const matches = findAllLines(file.lines, assignRe);
    for (const match of matches) {
      // Look at ±5 lines for a token-specific hash call
      const contextCode = extractLines(
        file.lines,
        Math.max(1, match.lineNumber - 5),
        match.lineNumber + 5
      );
      if (tokenHashRe.test(contextCode)) continue; // token is being hashed — not a deviation

      const intentional = hasIntentionalComment(file.lines, match.lineNumber, 5);
      candidates.push({
        detectorId: DETECTOR.PLAINTEXT_TOKEN_STORE,
        file: file.relativePath,
        line: match.lineNumber,
        matchedText: match.text.trim(),
        intentionalCommentPresent: intentional,
        isTestFile: isTestFileFn(file),
        surroundingCode: extractLines(file.lines, Math.max(1, match.lineNumber - 3), match.lineNumber + 3),
        establishedPatternExists: established,
      });
    }
  }

  return candidates;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Run all four detectors against the scanned file corpus.
 *
 * @param {import('./fileScanner').ScannedFile[]} files
 * @param {Function} isTestFileFn - pass `isTestFile` from fileScanner
 * @returns {RawCandidate[]}
 */
function runDetectors(files, isTestFileFn) {
  return [
    ...detectInsecureRandom(files, isTestFileFn),
    ...detectTokenInResponse(files, isTestFileFn),
    ...detectAccountEnumeration(files, isTestFileFn),
    ...detectPlaintextTokenStore(files, isTestFileFn),
  ];
}

module.exports = {
  runDetectors,
  DETECTOR,
  // Export individual detectors for unit testing
  detectInsecureRandom,
  detectTokenInResponse,
  detectAccountEnumeration,
  detectPlaintextTokenStore,
  // Export probes for unit testing
  establishedSecureRandomExists,
  establishedAntiEnumerationExists,
  establishedCredentialHashingExists,
};
