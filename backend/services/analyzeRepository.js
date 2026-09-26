/**
 * analyzeRepository.js
 *
 * Entry point for the Security Drift M1-A backend analysis engine.
 *
 * Accepts a repository path as a function argument and executes the full
 * analysis pipeline:
 *
 *   1. Validate the repository path.
 *   2. Parse SECURITY_PATTERNS.md (if present).
 *   3. Enumerate security-relevant source files.
 *   4. Run all four drift detectors.
 *   5. Classify candidates.
 *   6. Return a structured AnalysisResult.
 *
 * This module does NOT:
 *   - Expose an HTTP endpoint.
 *   - Modify any files in the analyzed repository.
 *   - Perform automatic remediation.
 *   - Install or require any third-party dependencies.
 */

"use strict";

const fs   = require("fs");
const path = require("path");

const { parseSecurityPatterns }               = require("./patternParser");
const { scanRepository, isTestFile }          = require("./fileScanner");
const { runDetectors }                        = require("./driftDetector");
const { classifyAll, CATEGORY }               = require("./findingClassifier");

/**
 * @typedef {import('./findingClassifier').AnalysisResult} AnalysisResult
 */

/**
 * Analyse a repository for security drift against its documented baseline.
 *
 * @param {string} repoPath - Absolute or relative path to the repository root.
 * @returns {AnalysisResult & { meta: object }}
 * @throws {Error} If the path does not exist or is not a directory.
 */
function analyzeRepository(repoPath) {
  // ── 1. Validate path ───────────────────────────────────────────────────
  const resolved = path.resolve(repoPath);

  if (!fs.existsSync(resolved)) {
    throw new Error(`Repository path does not exist: ${resolved}`);
  }

  const stat = fs.statSync(resolved);
  if (!stat.isDirectory()) {
    throw new Error(`Repository path is not a directory: ${resolved}`);
  }

  // ── 2. Parse SECURITY_PATTERNS.md ─────────────────────────────────────
  const parsedPatterns = parseSecurityPatterns(resolved);
  const hasBaseline    = parsedPatterns !== null;
  const baselineSections = hasBaseline ? parsedPatterns.sections : [];

  // ── 3. Enumerate source files ──────────────────────────────────────────
  const files = scanRepository(resolved);

  // ── 4. Run detectors ───────────────────────────────────────────────────
  const candidates = runDetectors(files, isTestFile);

  // ── 5. Classify ────────────────────────────────────────────────────────
  const result = classifyAll(candidates);

  // ── 6. Attach metadata ─────────────────────────────────────────────────
  result.meta = {
    repoPath:          resolved,
    baselineFile:      hasBaseline ? "SECURITY_PATTERNS.md" : null,
    baselinePresent:   hasBaseline,
    baselineSections:  baselineSections.map((s) => ({
      name:  s.name,
      rules: s.rules.length,
    })),
    filesScanned:      files.length,
    analysedAt:        new Date().toISOString(),
  };

  return result;
}

module.exports = { analyzeRepository, CATEGORY };
