/**
 * analysis.test.js
 *
 * Unit tests for the Security Drift M1-A backend analysis engine.
 *
 * Test requirements covered:
 *   T-1  The demo repository can be analyzed end-to-end.
 *   T-2  Math.random() drift is detected as a candidate (F-1 equivalent).
 *   T-3  The other three confirmed drift categories are detected.
 *   T-4  A uniformly absent control is classified as GENERAL_GAP, not drift.
 *   T-5  Intentional/documented behavior is not classified as CONFIRMED_DRIFT.
 *   T-6  node_modules and generated dirs are excluded from scanning.
 *
 * Temporary fixtures are written to os.tmpdir() for isolation — the real
 * repository files are never modified.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const os   = require("os");

// ── Services under test ───────────────────────────────────────────────────────
const { parseSecurityPatterns, hasSectionContaining, findSection } = require("../services/patternParser");
const { scanRepository, isTestFile }                               = require("../services/fileScanner");
const {
  runDetectors,
  detectInsecureRandom,
  detectTokenInResponse,
  detectAccountEnumeration,
  detectPlaintextTokenStore,
  establishedSecureRandomExists,
  establishedAntiEnumerationExists,
  establishedCredentialHashingExists,
  DETECTOR,
} = require("../services/driftDetector");
const { classifyAll, CATEGORY } = require("../services/findingClassifier");
const { analyzeRepository }     = require("../services/analyzeRepository");

// ── Fixture helpers ───────────────────────────────────────────────────────────

/**
 * Create a temporary directory tree from a map of
 * { relPath: fileContent }.  Returns the root path.
 */
function makeTmpRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sd-test-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(root, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf8");
  }
  return root;
}

/**
 * Remove a temporary directory recursively.
 */
function removeTmpRepo(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// patternParser
// ─────────────────────────────────────────────────────────────────────────────

describe("patternParser", () => {
  let tmpDir;

  afterEach(() => {
    if (tmpDir) { removeTmpRepo(tmpDir); tmpDir = null; }
  });

  test("returns null when SECURITY_PATTERNS.md does not exist", () => {
    tmpDir = makeTmpRepo({});
    expect(parseSecurityPatterns(tmpDir)).toBeNull();
  });

  test("parses sections and rules from the demo SECURITY_PATTERNS.md", () => {
    // Use the real repository baseline
    const result = parseSecurityPatterns(path.resolve(__dirname, "../.."));
    expect(result).not.toBeNull();
    expect(result.sections.length).toBeGreaterThan(0);
  });

  test("extracts correct section names and rule counts", () => {
    tmpDir = makeTmpRepo({
      "SECURITY_PATTERNS.md": [
        "# Security Patterns",
        "",
        "## Password Security",
        "",
        "- Passwords must be hashed using bcrypt.",
        "- Passwords must never be stored in plaintext.",
        "",
        "## Authentication",
        "",
        "- Authentication uses JWT.",
      ].join("\n"),
    });
    const result = parseSecurityPatterns(tmpDir);
    expect(result.sections).toHaveLength(2);
    expect(result.sections[0].name).toBe("Password Security");
    expect(result.sections[0].rules).toHaveLength(2);
    expect(result.sections[1].name).toBe("Authentication");
    expect(result.sections[1].rules).toHaveLength(1);
  });

  test("hasSectionContaining returns true for existing keyword", () => {
    const result = parseSecurityPatterns(path.resolve(__dirname, "../.."));
    expect(hasSectionContaining(result.sections, "Password")).toBe(true);
    expect(hasSectionContaining(result.sections, "Randomness")).toBe(true);
  });

  test("hasSectionContaining returns false for absent keyword", () => {
    const result = parseSecurityPatterns(path.resolve(__dirname, "../.."));
    expect(hasSectionContaining(result.sections, "OAuth2")).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// fileScanner
// ─────────────────────────────────────────────────────────────────────────────

describe("fileScanner", () => {
  let tmpDir;

  afterEach(() => {
    if (tmpDir) { removeTmpRepo(tmpDir); tmpDir = null; }
  });

  // T-6: node_modules and generated dirs are excluded
  test("T-6 — does not scan node_modules", () => {
    tmpDir = makeTmpRepo({
      "node_modules/evil/auth.js": 'const x = Math.random();',
      "routes/authRoutes.js":      'const crypto = require("crypto");',
    });
    const files = scanRepository(tmpDir);
    const paths = files.map((f) => f.relativePath.replace(/\\/g, "/"));
    expect(paths.some((p) => p.startsWith("node_modules/"))).toBe(false);
    expect(paths.some((p) => p.includes("authRoutes"))).toBe(true);
  });

  test("T-6 — does not scan .git directory", () => {
    tmpDir = makeTmpRepo({
      ".git/config": "some git config",
      "routes/authRoutes.js": 'const jwt = require("jsonwebtoken");',
    });
    const files = scanRepository(tmpDir);
    const paths = files.map((f) => f.relativePath.replace(/\\/g, "/"));
    expect(paths.some((p) => p.startsWith(".git/"))).toBe(false);
  });

  test("T-6 — does not scan dist directory", () => {
    tmpDir = makeTmpRepo({
      "dist/bundle.js":        "compiled code",
      "routes/authRoutes.js":  'const jwt = require("jsonwebtoken");',
    });
    const files = scanRepository(tmpDir);
    const paths = files.map((f) => f.relativePath.replace(/\\/g, "/"));
    expect(paths.some((p) => p.startsWith("dist/"))).toBe(false);
  });

  test("includes files in routes/ and models/ directories", () => {
    tmpDir = makeTmpRepo({
      "routes/authRoutes.js": 'router.post("/login", () => {});',
      "models/user.js":       'const mongoose = require("mongoose");',
    });
    const files = scanRepository(tmpDir);
    const paths = files.map((f) => f.relativePath.replace(/\\/g, "/"));
    expect(paths).toContain("routes/authRoutes.js");
    expect(paths).toContain("models/user.js");
  });

  test("isTestFile correctly identifies test files", () => {
    tmpDir = makeTmpRepo({
      "tests/auth.test.js": "test('x', () => {})",
      "routes/authRoutes.js": "// source",
    });
    const files = scanRepository(tmpDir);
    const testFiles   = files.filter(isTestFile);
    const sourceFiles = files.filter((f) => !isTestFile(f));
    const testPaths   = testFiles.map((f) => f.relativePath.replace(/\\/g, "/"));
    const srcPaths    = sourceFiles.map((f) => f.relativePath.replace(/\\/g, "/"));
    expect(testPaths).toContain("tests/auth.test.js");
    expect(srcPaths).toContain("routes/authRoutes.js");
  });

  test("returns file content and numbered lines", () => {
    tmpDir = makeTmpRepo({
      "routes/authRoutes.js": "line one\nline two\nline three",
    });
    const files = scanRepository(tmpDir);
    expect(files).toHaveLength(1);
    expect(files[0].lines[0]).toEqual({ lineNumber: 1, text: "line one" });
    expect(files[0].lines[1]).toEqual({ lineNumber: 2, text: "line two" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// driftDetector — established-pattern probes
// ─────────────────────────────────────────────────────────────────────────────

describe("driftDetector — established-pattern probes", () => {
  function makeFiles(contents) {
    return contents.map((content, i) => {
      const lines = content.split("\n").map((text, j) => ({ lineNumber: j + 1, text }));
      return { relativePath: `routes/file${i}.js`, content, lines };
    });
  }

  test("establishedSecureRandomExists returns true when crypto.randomBytes is present", () => {
    const files = makeFiles(['const token = crypto.randomBytes(32).toString("hex");']);
    expect(establishedSecureRandomExists(files, isTestFile)).toBe(true);
  });

  test("establishedSecureRandomExists returns false when only Math.random is present", () => {
    const files = makeFiles(["const token = Math.random().toString(36);"]);
    expect(establishedSecureRandomExists(files, isTestFile)).toBe(false);
  });

  test("establishedAntiEnumerationExists returns true when unified error message present", () => {
    const files = makeFiles(['return res.status(401).json({ message: "Invalid email or password" });']);
    expect(establishedAntiEnumerationExists(files, isTestFile)).toBe(true);
  });

  test("establishedCredentialHashingExists returns true when bcrypt.hash present", () => {
    const files = makeFiles(["const hash = await bcrypt.hash(password, 10);"]);
    expect(establishedCredentialHashingExists(files, isTestFile)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// driftDetector — individual detectors
// ─────────────────────────────────────────────────────────────────────────────

describe("driftDetector — detectInsecureRandom (D-1 / T-2)", () => {
  function makeFiles(contents) {
    return contents.map((content, i) => {
      const lines = content.split("\n").map((text, j) => ({ lineNumber: j + 1, text }));
      return { relativePath: `routes/auth${i}.js`, content, lines };
    });
  }

  // T-2: Math.random() deviation is detected
  test("T-2 — detects Math.random() in a file that also has a crypto.randomBytes reference", () => {
    const establishedFile = 'const token = crypto.randomBytes(32).toString("hex");';
    const deviantFile     = "const resetToken = Math.random().toString(36).substring(2,15);";
    const files = makeFiles([establishedFile, deviantFile]);
    const candidates = detectInsecureRandom(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].detectorId).toBe(DETECTOR.INSECURE_RANDOM);
    expect(candidates[0].establishedPatternExists).toBe(true);
  });

  // T-5: intentional comment prevents confirmed-drift classification
  test("T-5 — sets intentionalCommentPresent=true when INTENTIONALLY INSECURE comment is near", () => {
    const files = makeFiles([
      [
        'const token = crypto.randomBytes(32).toString("hex");',       // established
      ].join("\n"),
      [
        "// INTENTIONALLY INSECURE: Math.random() is not suitable.",
        "const resetToken = Math.random().toString(36).substring(2,15);",
      ].join("\n"),
    ]);
    const candidates = detectInsecureRandom(files, isTestFile);
    const deviantCandidates = candidates.filter((c) => c.file === "routes/auth1.js");
    expect(deviantCandidates.length).toBeGreaterThanOrEqual(1);
    expect(deviantCandidates[0].intentionalCommentPresent).toBe(true);
  });

  // T-4: absent pattern = GENERAL_GAP (Math.random present but no crypto.randomBytes anywhere)
  test("T-4 — sets establishedPatternExists=false when no crypto.randomBytes exists", () => {
    // Only Math.random — never used crypto.randomBytes anywhere
    const files = makeFiles(["const x = Math.random().toString(36);"]);
    const candidates = detectInsecureRandom(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].establishedPatternExists).toBe(false);
  });

  // T-6: test files produce isTestFile=true on the candidate
  test("T-6 — flags candidates from test files with isTestFile=true", () => {
    const files = [
      {
        relativePath: "tests/auth.test.js",
        content: "const t = Math.random().toString(36);",
        lines: [{ lineNumber: 1, text: "const t = Math.random().toString(36);" }],
      },
    ];
    const candidates = detectInsecureRandom(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].isTestFile).toBe(true);
  });
});

describe("driftDetector — detectTokenInResponse (D-2 / T-3)", () => {
  function makeFile(content, relPath = "routes/authRoutes.js") {
    const lines = content.split("\n").map((text, i) => ({ lineNumber: i + 1, text }));
    return [{ relativePath: relPath, content, lines }];
  }

  test("T-3 — detects resetToken returned in res.json()", () => {
    const content = [
      'res.json({',
      '  message: "Password reset token generated",',
      '  resetToken',
      '});',
    ].join("\n");
    const files = makeFile(content);
    const candidates = detectTokenInResponse(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].detectorId).toBe(DETECTOR.TOKEN_IN_RESPONSE);
  });

  test("does not flag resetToken when it is only in a DB assignment (no nearby res.json)", () => {
    const content = "user.resetToken = resetToken;\nawait user.save();";
    const files = makeFile(content);
    const candidates = detectTokenInResponse(files, isTestFile);
    expect(candidates).toHaveLength(0);
  });
});

describe("driftDetector — detectAccountEnumeration (D-3 / T-3)", () => {
  function makeFile(content, relPath = "routes/authRoutes.js") {
    const lines = content.split("\n").map((text, i) => ({ lineNumber: i + 1, text }));
    return [{ relativePath: relPath, content, lines }];
  }

  test("T-3 — detects 'User not found' in a forgot-password context", () => {
    const content = [
      'router.post("/forgot-password", async (req, res) => {',
      '  const user = await User.findOne({ email });',
      '  if (!user) {',
      '    return res.status(404).json({ message: "User not found" });',
      '  }',
      "});",
    ].join("\n");
    const files = makeFile(content);
    const candidates = detectAccountEnumeration(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].detectorId).toBe(DETECTOR.ACCOUNT_ENUMERATION);
  });

  test("does not flag 'User not found' outside of a reset/forgot context", () => {
    // A profile endpoint that happens to return 404
    const content = [
      'router.get("/profile", async (req, res) => {',
      '  if (!user) return res.status(404).json({ message: "User not found" });',
      "});",
    ].join("\n");
    const files = makeFile(content, "routes/profileRoutes.js");
    const candidates = detectAccountEnumeration(files, isTestFile);
    expect(candidates).toHaveLength(0);
  });
});

describe("driftDetector — detectPlaintextTokenStore (D-4 / T-3)", () => {
  function makeFiles(contents) {
    return contents.map((content, i) => {
      const lines = content.split("\n").map((text, j) => ({ lineNumber: j + 1, text }));
      return { relativePath: `routes/auth${i}.js`, content, lines };
    });
  }

  test("T-3 — detects plaintext .resetToken assignment without hashing", () => {
    const content = [
      "const hashedPassword = await bcrypt.hash(password, 10);",  // established pattern
      "user.resetToken = resetToken;",                            // deviation
    ].join("\n");
    const files = makeFiles([content]);
    const candidates = detectPlaintextTokenStore(files, isTestFile);
    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates[0].detectorId).toBe(DETECTOR.PLAINTEXT_TOKEN_STORE);
  });

  test("does not flag .resetToken assignment when hashing is present in context", () => {
    const content = [
      'const resetTokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");',
      "user.resetToken = resetTokenHash;",
    ].join("\n");
    const files = makeFiles([content]);
    const candidates = detectPlaintextTokenStore(files, isTestFile);
    expect(candidates).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// findingClassifier
// ─────────────────────────────────────────────────────────────────────────────

describe("findingClassifier — classifyAll", () => {
  function makeCandidate(overrides) {
    return {
      detectorId: DETECTOR.INSECURE_RANDOM,
      file: "routes/authRoutes.js",
      line: 10,
      matchedText: "const t = Math.random().toString(36);",
      intentionalCommentPresent: false,
      isTestFile: false,
      surroundingCode: "const t = Math.random().toString(36);",
      establishedPatternExists: true,
      ...overrides,
    };
  }

  test("CONFIRMED_DRIFT when established pattern exists, no intentional comment, not test", () => {
    const result = classifyAll([makeCandidate()]);
    expect(result.confirmedDrift).toHaveLength(1);
    expect(result.confirmedDrift[0].category).toBe(CATEGORY.CONFIRMED_DRIFT);
    expect(result.confirmedDrift[0].status).toBe("OPEN");
  });

  test("T-4 — GENERAL_GAP when established pattern does NOT exist", () => {
    const result = classifyAll([makeCandidate({ establishedPatternExists: false })]);
    expect(result.confirmedDrift).toHaveLength(0);
    const gapFindings = result.excluded.filter((f) => f.category === CATEGORY.GENERAL_GAP);
    expect(gapFindings).toHaveLength(1);
  });

  test("T-5 — INTENTIONAL_DESIGN when intentional comment is present", () => {
    const result = classifyAll([makeCandidate({ intentionalCommentPresent: true })]);
    expect(result.confirmedDrift).toHaveLength(0);
    const intFindings = result.excluded.filter((f) => f.category === CATEGORY.INTENTIONAL_DESIGN);
    expect(intFindings).toHaveLength(1);
  });

  test("T-6 — TEST_ARTIFACT when candidate is from a test file", () => {
    const result = classifyAll([makeCandidate({ isTestFile: true })]);
    expect(result.confirmedDrift).toHaveLength(0);
    const testFindings = result.excluded.filter((f) => f.category === CATEGORY.TEST_ARTIFACT);
    expect(testFindings).toHaveLength(1);
  });

  test("summary counts are correct", () => {
    const candidates = [
      makeCandidate({ line: 10 }),                                           // CONFIRMED_DRIFT
      makeCandidate({ line: 20, establishedPatternExists: false }),          // GENERAL_GAP
      makeCandidate({ line: 30, intentionalCommentPresent: true }),          // INTENTIONAL_DESIGN
      makeCandidate({ line: 40, isTestFile: true }),                         // TEST_ARTIFACT
    ];
    const result = classifyAll(candidates);
    expect(result.summary.potentialDeviations).toBe(4);
    expect(result.summary.confirmedDrift).toBe(1);
    expect(result.summary.excluded).toBe(3);
    expect(result.summary.remainingDrift).toBe(1);
  });

  test("deduplicates candidates with same detector+file+line", () => {
    const c = makeCandidate();
    const result = classifyAll([c, c, c]);
    expect(result.findings).toHaveLength(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// analyzeRepository — end-to-end on the demo repository (T-1)
// ─────────────────────────────────────────────────────────────────────────────

describe("analyzeRepository — demo repository (T-1)", () => {
  const DEMO_REPO = path.resolve(__dirname, "../..");

  test("T-1 — runs without error on the demo repository", () => {
    expect(() => analyzeRepository(DEMO_REPO)).not.toThrow();
  });

  test("T-1 — returns meta with baselinePresent=true", () => {
    const result = analyzeRepository(DEMO_REPO);
    expect(result.meta.baselinePresent).toBe(true);
    expect(result.meta.baselineFile).toBe("SECURITY_PATTERNS.md");
  });

  test("T-1 — scans at least one source file", () => {
    const result = analyzeRepository(DEMO_REPO);
    expect(result.meta.filesScanned).toBeGreaterThan(0);
  });

  test("T-2 — F-1 equivalent: Math.random() drift is in confirmedDrift (INTENTIONAL_DESIGN because of comment)", () => {
    // The demo repo has Math.random() WITH an INTENTIONALLY INSECURE comment.
    // Per the classification rules this is INTENTIONAL_DESIGN, not CONFIRMED_DRIFT.
    // This is the correct, expected result.
    const result = analyzeRepository(DEMO_REPO);
    const allD1  = result.findings.filter((f) => f.detectorId === "D-1");
    expect(allD1.length).toBeGreaterThanOrEqual(1);
    // The source file D-1 candidate should be INTENTIONAL_DESIGN
    const sourceD1 = allD1.find((f) => f.category !== CATEGORY.TEST_ARTIFACT);
    expect(sourceD1).toBeDefined();
    expect(sourceD1.category).toBe(CATEGORY.INTENTIONAL_DESIGN);
  });

  test("T-3 — D-2 (token in response) produces a finding", () => {
    const result  = analyzeRepository(DEMO_REPO);
    const d2Findings = result.findings.filter((f) => f.detectorId === "D-2");
    expect(d2Findings.length).toBeGreaterThanOrEqual(1);
  });

  test("T-3 — D-3 (account enumeration) produces a finding", () => {
    const result  = analyzeRepository(DEMO_REPO);
    const d3Findings = result.findings.filter((f) => f.detectorId === "D-3");
    expect(d3Findings.length).toBeGreaterThanOrEqual(1);
  });

  test("T-3 — D-4 (plaintext token store) produces a finding", () => {
    const result  = analyzeRepository(DEMO_REPO);
    const d4Findings = result.findings.filter((f) => f.detectorId === "D-4");
    expect(d4Findings.length).toBeGreaterThanOrEqual(1);
  });

  test("T-1 — result has confirmedDrift, excluded and summary keys", () => {
    const result = analyzeRepository(DEMO_REPO);
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.confirmedDrift)).toBe(true);
    expect(Array.isArray(result.excluded)).toBe(true);
    expect(result.summary).toBeDefined();
    expect(typeof result.summary.potentialDeviations).toBe("number");
    expect(typeof result.summary.confirmedDrift).toBe("number");
    expect(typeof result.summary.excluded).toBe("number");
    expect(typeof result.summary.remainingDrift).toBe("number");
  });

  test("T-6 — no findings from node_modules paths", () => {
    const result = analyzeRepository(DEMO_REPO);
    const nmFindings = result.findings.filter((f) =>
      f.file.replace(/\\/g, "/").includes("node_modules/")
    );
    expect(nmFindings).toHaveLength(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// analyzeRepository — isolated fixture repos
// ─────────────────────────────────────────────────────────────────────────────

describe("analyzeRepository — fixture repos", () => {
  let tmpDir;

  afterEach(() => {
    if (tmpDir) { removeTmpRepo(tmpDir); tmpDir = null; }
  });

  const PATTERNS_MD = [
    "# Security Patterns",
    "",
    "## Security-Sensitive Randomness",
    "",
    "- Security-sensitive tokens must use a cryptographically secure random generator.",
    "- Math.random() must not be used for authentication or password-reset tokens.",
    "",
    "## Password Security",
    "",
    "- User passwords must be hashed using bcrypt.",
    "- Passwords must never be stored in plaintext.",
    "",
    "## Authentication",
    "",
    "- Authentication uses JWT.",
    "- Login should use a unified error message to prevent enumeration.",
    "",
    "## Sensitive Data",
    "",
    "- Passwords should never be returned in API responses.",
    "- Sensitive tokens should be handled securely.",
    "",
    "## Password Reset",
    "",
    "- Reset tokens must be unpredictable.",
    "- Password reset responses should avoid revealing whether an account exists.",
  ].join("\n");

  // Deviant auth file: contains all four drift patterns but NO intentional comments
  // and the established patterns exist in a separate reference file.
  const REFERENCE_FILE = [
    '// Reference implementation — establishes the secure patterns',
    'const crypto = require("crypto");',
    'const bcrypt = require("bcryptjs");',
    '',
    '// Established: secure random',
    'const secureToken = crypto.randomBytes(32).toString("hex");',
    '',
    '// Established: bcrypt hashing',
    'const hashedPwd = await bcrypt.hash(password, 10);',
    '',
    '// Established: anti-enumeration',
    'return res.status(401).json({ message: "Invalid email or password" });',
    '',
    '// Established: JWT (login returns the JWT deliberately)',
    'const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "1h" });',
  ].join("\n");

  const DEVIANT_FILE = [
    'router.post("/forgot-password", async (req, res) => {',
    '  const user = await User.findOne({ email });',
    '  if (!user) {',
    '    return res.status(404).json({ message: "User not found" });',  // D-3
    '  }',
    '  const resetToken = Math.random().toString(36).substring(2, 15);', // D-1
    '  user.resetToken = resetToken;',                                  // D-4
    '  await user.save();',
    '  res.json({',
    '    message: "Password reset token generated",',
    '    resetToken',                                                    // D-2
    '  });',
    '});',
  ].join("\n");

  test("detects all four drift categories in a minimal deviant fixture", () => {
    tmpDir = makeTmpRepo({
      "SECURITY_PATTERNS.md":       PATTERNS_MD,
      "routes/reference.js":        REFERENCE_FILE,
      "routes/forgotPassword.js":   DEVIANT_FILE,
    });
    const result = analyzeRepository(tmpDir);

    const detectorIds = result.findings.map((f) => f.detectorId);
    expect(detectorIds).toContain("D-1");
    expect(detectorIds).toContain("D-2");
    expect(detectorIds).toContain("D-3");
    expect(detectorIds).toContain("D-4");
  });

  test("all four are CONFIRMED_DRIFT in the deviant fixture (no intentional comments)", () => {
    tmpDir = makeTmpRepo({
      "SECURITY_PATTERNS.md":       PATTERNS_MD,
      "routes/reference.js":        REFERENCE_FILE,
      "routes/forgotPassword.js":   DEVIANT_FILE,
    });
    const result = analyzeRepository(tmpDir);
    const driftIds = result.confirmedDrift.map((f) => f.detectorId);
    expect(driftIds).toContain("D-1");
    expect(driftIds).toContain("D-2");
    expect(driftIds).toContain("D-3");
    expect(driftIds).toContain("D-4");
  });

  // T-4: a repo where Math.random is present but crypto.randomBytes is NEVER used
  test("T-4 — Math.random() without any crypto.randomBytes is GENERAL_GAP not CONFIRMED_DRIFT", () => {
    tmpDir = makeTmpRepo({
      "SECURITY_PATTERNS.md": PATTERNS_MD,
      // Only deviant code — no established secure random pattern anywhere
      "routes/authRoutes.js": [
        'const bcrypt = require("bcryptjs");',
        'const hashedPwd = await bcrypt.hash(password, 10);',
        'return res.status(401).json({ message: "Invalid email or password" });',
        "// Only insecure random — never used crypto.randomBytes",
        "const token = Math.random().toString(36);",
      ].join("\n"),
    });
    const result = analyzeRepository(tmpDir);
    const d1Findings = result.findings.filter((f) => f.detectorId === "D-1");
    expect(d1Findings.length).toBeGreaterThanOrEqual(1);
    const d1NonTest = d1Findings.filter((f) => !f.isTestFile);
    for (const f of d1NonTest) {
      expect(f.category).toBe(CATEGORY.GENERAL_GAP);
    }
  });

  // T-5: intentional comment marks the deviation as INTENTIONAL_DESIGN
  test("T-5 — intentional comment produces INTENTIONAL_DESIGN not CONFIRMED_DRIFT", () => {
    tmpDir = makeTmpRepo({
      "SECURITY_PATTERNS.md": PATTERNS_MD,
      "routes/reference.js":  REFERENCE_FILE,
      "routes/authRoutes.js": [
        "// INTENTIONALLY INSECURE: using Math.random for demo purposes",
        "const resetToken = Math.random().toString(36).substring(2, 15);",
      ].join("\n"),
    });
    const result = analyzeRepository(tmpDir);
    const d1Findings = result.findings.filter((f) => f.detectorId === "D-1");
    const sourceD1   = d1Findings.filter((f) => f.category !== CATEGORY.TEST_ARTIFACT);
    expect(sourceD1.length).toBeGreaterThanOrEqual(1);
    for (const f of sourceD1) {
      expect(f.category).toBe(CATEGORY.INTENTIONAL_DESIGN);
    }
    // Must NOT appear as confirmed drift
    const driftIds = result.confirmedDrift.map((f) => f.detectorId);
    expect(driftIds.filter((id) => id === "D-1")).toHaveLength(0);
  });

  test("throws an error for a non-existent path", () => {
    expect(() => analyzeRepository("/tmp/this-does-not-exist-sd-test")).toThrow();
  });

  test("throws an error when path is a file, not a directory", () => {
    tmpDir = makeTmpRepo({ "somefile.js": "// hello" });
    const filePath = path.join(tmpDir, "somefile.js");
    expect(() => analyzeRepository(filePath)).toThrow();
  });

  test("handles a repository with no SECURITY_PATTERNS.md gracefully", () => {
    tmpDir = makeTmpRepo({
      "routes/authRoutes.js": [
        'const bcrypt = require("bcryptjs");',
        'const hashedPwd = await bcrypt.hash(password, 10);',
      ].join("\n"),
    });
    const result = analyzeRepository(tmpDir);
    expect(result.meta.baselinePresent).toBe(false);
    expect(result.meta.baselineFile).toBeNull();
    // Analysis still runs; just no document-verified rules
    expect(Array.isArray(result.findings)).toBe(true);
  });
});
