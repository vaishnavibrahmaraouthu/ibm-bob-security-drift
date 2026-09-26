/**
 * patternParser.js
 *
 * Reads SECURITY_PATTERNS.md from the supplied repository root and returns a
 * structured list of named security-pattern sections, each with its rules as
 * plain strings.
 *
 * Format expected in SECURITY_PATTERNS.md:
 *   ## Section Name
 *   - Rule text one.
 *   - Rule text two.
 *
 * Only the standard library (fs, path) is used.
 */

"use strict";

const fs   = require("fs");
const path = require("path");

/**
 * @typedef {Object} PatternSection
 * @property {string}   name  - Section heading (e.g. "Password Security")
 * @property {string[]} rules - Individual rule strings from bullet points
 */

/**
 * Parse SECURITY_PATTERNS.md at the given repository root.
 *
 * @param {string} repoPath - Absolute or relative path to the repository root.
 * @returns {{ sections: PatternSection[], raw: string } | null}
 *   Returns null if the file does not exist.
 */
function parseSecurityPatterns(repoPath) {
  const filePath = path.join(repoPath, "SECURITY_PATTERNS.md");

  if (!fs.existsSync(filePath)) {
    return null;
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const sections = [];
  let currentSection = null;

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.trimEnd();

    // Level-2 heading → new section
    if (/^## /.test(line)) {
      const name = line.replace(/^## /, "").trim();
      currentSection = { name, rules: [] };
      sections.push(currentSection);
      continue;
    }

    // Bullet point inside an active section → rule
    if (currentSection && /^- /.test(line)) {
      const rule = line.replace(/^- /, "").trim();
      if (rule) {
        currentSection.rules.push(rule);
      }
    }
  }

  return { sections, raw };
}

/**
 * Return true if a section whose name matches the given keyword exists in the
 * parsed patterns and has at least one rule.
 *
 * @param {PatternSection[]} sections
 * @param {string} keyword - Case-insensitive substring to match against section names.
 * @returns {boolean}
 */
function hasSectionContaining(sections, keyword) {
  const lc = keyword.toLowerCase();
  return sections.some(
    (s) => s.name.toLowerCase().includes(lc) && s.rules.length > 0
  );
}

/**
 * Return the first section whose name matches keyword, or null.
 *
 * @param {PatternSection[]} sections
 * @param {string} keyword
 * @returns {PatternSection | null}
 */
function findSection(sections, keyword) {
  const lc = keyword.toLowerCase();
  return sections.find((s) => s.name.toLowerCase().includes(lc)) || null;
}

module.exports = { parseSecurityPatterns, hasSectionContaining, findSection };
