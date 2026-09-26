/**
 * analysisApi.test.js
 *
 * API-level tests for POST /api/analysis.
 *
 * Tests cover:
 *   - valid repository path returns 200 with a structured result
 *   - missing repositoryPath returns 400
 *   - non-string repositoryPath returns 400
 *   - non-existent path returns 400
 *   - path to a file (not a directory) returns 400
 *   - response structure contains expected top-level keys
 *   - existing analysis engine behavior remains intact (findings present)
 */

"use strict";

const request = require("supertest");
const fs      = require("fs");
const path    = require("path");
const os      = require("os");
const app     = require("../server");

const DEMO_REPO = path.resolve(__dirname, "../..");

// ── Fixture helpers ───────────────────────────────────────────────────────────

function makeTmpRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sd-api-test-"));
  for (const [relPath, content] of Object.entries(files)) {
    const full = path.join(root, relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf8");
  }
  return root;
}

function removeTmpRepo(root) {
  fs.rmSync(root, { recursive: true, force: true });
}

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/analysis", () => {
  // ── Input validation ────────────────────────────────────────────────────────

  test("returns 400 when repositoryPath is missing", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({});

    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe("repositoryPath is required");
  });

  test("returns 400 when repositoryPath is not a string", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: 42 });

    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe("repositoryPath must be a string");
  });

  test("returns 400 when repositoryPath does not exist", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: "/tmp/this-path-does-not-exist-sd-api" });

    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe("Repository path does not exist");
  });

  test("returns 400 when repositoryPath points to a file rather than a directory", async () => {
    const tmpDir = makeTmpRepo({ "somefile.js": "// hello" });
    const filePath = path.join(tmpDir, "somefile.js");

    try {
      const res = await request(app)
        .post("/api/analysis")
        .send({ repositoryPath: filePath });

      expect(res.statusCode).toBe(400);
      expect(res.body.message).toBe("Repository path must be a directory");
    } finally {
      removeTmpRepo(tmpDir);
    }
  });

  // ── Successful analysis ─────────────────────────────────────────────────────

  test("returns 200 with a valid repository path", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    expect(res.statusCode).toBe(200);
  });

  test("response body contains top-level keys: findings, confirmedDrift, excluded, summary, meta", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(Array.isArray(res.body.confirmedDrift)).toBe(true);
    expect(Array.isArray(res.body.excluded)).toBe(true);
    expect(res.body.summary).toBeDefined();
    expect(res.body.meta).toBeDefined();
  });

  test("summary contains numeric counts", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    const { summary } = res.body;
    expect(typeof summary.potentialDeviations).toBe("number");
    expect(typeof summary.confirmedDrift).toBe("number");
    expect(typeof summary.excluded).toBe("number");
    expect(typeof summary.remainingDrift).toBe("number");
  });

  test("meta reflects the analysed repository", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    const { meta } = res.body;
    expect(meta.baselinePresent).toBe(true);
    expect(meta.baselineFile).toBe("SECURITY_PATTERNS.md");
    expect(meta.filesScanned).toBeGreaterThan(0);
    expect(typeof meta.analysedAt).toBe("string");
  });

  test("findings include the expected detector IDs for the demo repo", async () => {
    // D-2 (token in response) was remediated (F-2 fix) — it no longer fires.
    // D-3 (account enumeration) and D-4 (plaintext token store) remain open.
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    const ids = res.body.findings.map((f) => f.detectorId);
    expect(ids).not.toContain("D-2");
    expect(ids).toContain("D-3");
    expect(ids).toContain("D-4");
  });

  test("confirmed drift findings have status OPEN", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    for (const f of res.body.confirmedDrift) {
      expect(f.status).toBe("OPEN");
    }
  });

  test("analysis engine behavior: no findings from node_modules", async () => {
    const res = await request(app)
      .post("/api/analysis")
      .send({ repositoryPath: DEMO_REPO });

    const nmFindings = res.body.findings.filter((f) =>
      (f.file || "").replace(/\\/g, "/").includes("node_modules/")
    );
    expect(nmFindings).toHaveLength(0);
  });
});
