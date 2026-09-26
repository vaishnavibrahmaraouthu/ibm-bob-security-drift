/**
 * fileScanner.js
 *
 * Enumerates JavaScript/Node.js source files inside a repository that are
 * relevant to security analysis, skipping all generated and dependency
 * directories.
 *
 * For each matched file returns:
 *   - absolute path
 *   - path relative to the repository root
 *   - file contents as a string
 *   - contents split into numbered lines: [{ lineNumber, text }]
 *
 * Only the standard library (fs, path) is used.
 */

"use strict";

const fs   = require("fs");
const path = require("path");

// Directories that are always excluded from scanning.
const EXCLUDED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "coverage",
  ".cache",
  "tmp",
  "temp",
  "out",
  "public",   // static assets
  "assets",
]);

// File extensions considered as JavaScript/Node.js source.
const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);

// Sub-directories that are particularly relevant for security analysis.
// Files in these directories are always included when they have a source ext.
const SECURITY_RELEVANT_DIRS = ["routes", "middleware", "models", "config", "services", "utils", "lib", "helpers", "auth"];

// Name fragments that suggest a file is security-relevant regardless of dir.
const SECURITY_RELEVANT_NAME_FRAGMENTS = ["auth", "password", "token", "jwt", "session", "crypto", "hash", "user", "login", "reset", "account"];

/**
 * @typedef {Object} ScannedFile
 * @property {string} absolutePath
 * @property {string} relativePath
 * @property {string} content
 * @property {{ lineNumber: number, text: string }[]} lines
 */

/**
 * Walk the repository directory tree and return all security-relevant source
 * files.  Test files (*.test.js, *.spec.js, files inside __tests__ or tests
 * directories) are included but tagged so callers can distinguish them.
 *
 * @param {string} repoPath - Root of the repository to scan.
 * @param {Set<string>} [excludeRelPaths] - Optional set of normalised relative
 *   paths (forward-slash separated) to skip.  Used by analyzeRepository to
 *   exclude the tool's own analysis-infrastructure files when scanning itself.
 * @returns {ScannedFile[]}
 */
function scanRepository(repoPath, excludeRelPaths) {
  const results = [];
  _walk(repoPath, repoPath, results, excludeRelPaths || new Set());
  return results;
}

/**
 * Recursive directory walk.
 *
 * @param {string} repoRoot
 * @param {string} dir
 * @param {ScannedFile[]} results
 * @param {Set<string>} excludeRelPaths
 */
function _walk(repoRoot, dir, results, excludeRelPaths) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // unreadable directory — skip silently
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath  = path.relative(repoRoot, fullPath);
    // Normalise to forward slashes for cross-platform comparison.
    const relNorm  = relPath.replace(/\\/g, "/");

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      _walk(repoRoot, fullPath, results, excludeRelPaths);
    } else if (entry.isFile()) {
      if (excludeRelPaths.has(relNorm)) continue;
      if (!_isSourceFile(entry.name)) continue;
      if (!_isRelevant(relPath, entry.name)) continue;
      _readFile(fullPath, relPath, results);
    }
  }
}

/**
 * Return true if the filename has a recognised source extension.
 */
function _isSourceFile(name) {
  return SOURCE_EXTENSIONS.has(path.extname(name).toLowerCase());
}

/**
 * Return true if the file is considered security-relevant.
 *
 * A file is relevant when it:
 *   - lives directly in the repository root (e.g. server.js, index.js, app.js), OR
 *   - lives inside a security-relevant directory, OR
 *   - has a security-relevant fragment in its name.
 */
function _isRelevant(relPath, name) {
  const nameLower = name.toLowerCase();
  const parts = relPath.split(path.sep);

  // Root-level files (depth 1) are always included.
  if (parts.length === 1) return true;

  // Check each path segment (directory names) for security relevance.
  for (const segment of parts.slice(0, -1)) {
    if (SECURITY_RELEVANT_DIRS.includes(segment.toLowerCase())) return true;
  }

  // Check filename fragments.
  for (const fragment of SECURITY_RELEVANT_NAME_FRAGMENTS) {
    if (nameLower.includes(fragment)) return true;
  }

  return false;
}

/**
 * Read a file and push a ScannedFile record onto results.
 */
function _readFile(absolutePath, relativePath, results) {
  let content;
  try {
    content = fs.readFileSync(absolutePath, "utf8");
  } catch {
    return; // unreadable file — skip silently
  }

  const lines = content.split("\n").map((text, i) => ({
    lineNumber: i + 1,
    text,
  }));

  results.push({ absolutePath, relativePath, content, lines });
}

/**
 * Return true if the file appears to be a test file.
 *
 * @param {ScannedFile} file
 */
function isTestFile(file) {
  const rel = file.relativePath.replace(/\\/g, "/");
  if (/\.(test|spec)\.(m?js|cjs)$/.test(rel)) return true;
  if (/(^|\/)(__tests__|tests|test)\//i.test(rel)) return true;
  return false;
}

module.exports = { scanRepository, isTestFile };
