import { useState } from "react";
import StatusBadge from "./StatusBadge";

function plainEnglishProblem(finding) {
  if (finding.problem || finding.summary) {
    return finding.problem || finding.summary;
  }

  const title = (finding.title || "").toLowerCase();
  if (title.includes("account enumeration")) {
    return "The password-reset response could reveal whether an email address has an account.";
  }
  if (title.includes("exposed") && title.includes("token")) {
    return "A password-reset token may be visible in an API response.";
  }
  if (title.includes("plaintext") || title.includes("token stored")) {
    return "A password-reset token is stored without the protection used for other credentials.";
  }
  if (title.includes("token generation") || title.includes("random")) {
    return "The password-reset token may be generated in a way that is easier to guess.";
  }

  return finding.classificationReason || finding.driftReason || finding.detectedImplementation || finding.title || "A security practice differs from the established repository pattern.";
}

function conciseText(value, maxLength = 260) {
  const text = typeof value === "string" ? value.replace(/\s+/g, " ").trim() : "";
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength).replace(/\s+\S*$/, "").trim()}...`;
}

function buildRemediationBrief(finding, location) {
  const repositoryPattern = finding.repositoryPattern || finding.patternViolated;
  const quotedPattern = repositoryPattern?.match(/["“]([^"”]+)["”]/)?.[1];
  const pattern = conciseText(quotedPattern || repositoryPattern) ||
    "Follow the security pattern already established in this project.";
  const constraints = finding.constraints || finding.remediationConstraints;
  const constraintList = Array.isArray(constraints) && constraints.length > 0
    ? constraints
    : [
        "Preserve the existing flow",
        "Do not modify unrelated findings",
        "Update and run relevant tests",
      ];

  return [
    "Security Drift Remediation",
    "",
    `Finding: ${finding.title || "Security finding"}`,
    `Severity: ${finding.severity || "Not specified"}`,
    `File: ${location || finding.file || "Not specified"}`,
    "",
    "Problem:",
    conciseText(plainEnglishProblem(finding)),
    "",
    "Repository pattern:",
    pattern,
    "",
    "Requested action:",
    conciseText(finding.remediation) || "Make the smallest targeted change that aligns this finding with the established repository pattern.",
    "",
    "Constraints:",
    ...constraintList.map((constraint) => `- ${constraint}`),
  ].join("\n");
}

// FindingCard — collapsible card showing the full investigation flow for a
// single drift finding.
//
// Supports both the live API finding shape (from analyzeRepository) and the
// legacy static finding shape (from findings.js) so the component works in
// both contexts without modification.
//
// Expanded body: Pattern → Detection → Why it's drift → Evidence → Remediation
export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const [briefOpen, setBriefOpen] = useState(false);
  const [copyMessage, setCopyMessage] = useState("");

  // ── Normalise fields that differ between API and static shapes ────────────

  // Location: API has { file, line }; static data has a pre-formatted `location`.
  const location =
    finding.location ||
    (finding.file && finding.line != null
      ? `${finding.file} — line ${finding.line}`
      : finding.file || "");

  // Verdict / classification reason
  const verdict = finding.verdict || finding.classificationReason || "";

  // Before/after panels — both shapes carry { label, code, impact/property }
  const hasBefore = finding.before && (finding.before.label || finding.before.code);
  const hasAfter  = finding.after  && (finding.after.label  || finding.after.code);
  const remediationBrief = buildRemediationBrief(finding, location);

  async function handleCopyBrief() {
    try {
      await navigator.clipboard.writeText(remediationBrief);
      setCopyMessage("Brief copied.");
    } catch {
      setCopyMessage("Copy unavailable. Select and copy the brief above.");
    }
  }

  return (
    <div className={`finding-card${expanded ? " finding-card--open" : ""}`}>

      {/* ── Header row ───────────────────────────────────────────────── */}
      <button
        className="finding-header"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
      >
        <span className="finding-id">{finding.id}</span>

        <span className="finding-badges">
          <StatusBadge type="severity" value={finding.severity} />
          <StatusBadge type="status"   value={finding.status} />
        </span>

        <span className="finding-title">{finding.title}</span>

        <span className="finding-location">{finding.file}</span>

        <span className="finding-chevron" aria-hidden="true">
          {expanded ? "▲" : "▼"}
        </span>
      </button>

      {/* ── Expanded investigation body ──────────────────────────────── */}
      {expanded && (
        <div className="finding-body">

          {/* A. Repository pattern */}
          {finding.repositoryPattern && (
            <div className="inv-section">
              <div className="inv-label inv-label--pattern">
                <span className="inv-step" aria-hidden="true">A</span>
                Established repository pattern
              </div>
              <p className="inv-text">{finding.repositoryPattern}</p>
            </div>
          )}

          {/* B. Detected implementation */}
          {finding.detectedImplementation && (
            <div className="inv-section">
              <div className="inv-label inv-label--detected">
                <span className="inv-step" aria-hidden="true">B</span>
                Detected implementation
              </div>
              <p className="inv-text">{finding.detectedImplementation}</p>
              {location && (
                <div className="inv-location">
                  <span className="inv-loc-label">Location</span>
                  <code className="inv-loc-value">{location}</code>
                </div>
              )}
              {finding.surroundingCode && (
                <pre className="ba-code">{finding.surroundingCode}</pre>
              )}
            </div>
          )}

          {/* C. Why this is classified as drift */}
          {finding.driftReason && (
            <div className="inv-section inv-section--drift">
              <div className="inv-label inv-label--drift">
                <span className="inv-step" aria-hidden="true">C</span>
                Why this is classified as security drift
              </div>
              <p className="inv-text">{finding.driftReason}</p>
              {verdict && (
                <div className="inv-verdict">
                  <span className="inv-loc-label">Classification</span>
                  <span className="inv-verdict-text">{verdict}</span>
                </div>
              )}
            </div>
          )}

          {/* D. Code evidence: before → after */}
          {(hasBefore || hasAfter) && (
            <div className="inv-section">
              <div className="inv-label inv-label--evidence">
                <span className="inv-step" aria-hidden="true">D</span>
                Code evidence
              </div>
              <div className="before-after">
                {hasBefore && (
                  <div className="ba-panel ba-before">
                    <div className="ba-label">Before</div>
                    {finding.before.label && (
                      <p className="ba-description">{finding.before.label}</p>
                    )}
                    {finding.before.code && (
                      <pre className="ba-code">{finding.before.code}</pre>
                    )}
                    {finding.before.impact && (
                      <p className="ba-impact">{finding.before.impact}</p>
                    )}
                  </div>
                )}
                {hasAfter && (
                  <div className="ba-panel ba-after">
                    <div className="ba-label">After</div>
                    {finding.after.label && (
                      <p className="ba-description">{finding.after.label}</p>
                    )}
                    {finding.after.code && (
                      <pre className="ba-code">{finding.after.code}</pre>
                    )}
                    {finding.after.property && (
                      <p className="ba-property">{finding.after.property}</p>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* E. Remediation guidance */}
          <div className="inv-section inv-section--verified">
            <div className="inv-label inv-label--verified">
              <span className="inv-step" aria-hidden="true">E</span>
              Remediation &amp; verification
            </div>
            <button
              type="button"
              onClick={() => {
                setCopyMessage("");
                setBriefOpen(true);
              }}
              style={{
                margin: "0 0 12px",
                padding: "8px 12px",
                color: "var(--sd-text)",
                background: "var(--sd-surface-2)",
                border: "1px solid var(--sd-border-2)",
                borderRadius: "var(--sd-radius-sm)",
                fontSize: "13px",
                fontWeight: 600,
              }}
            >
              Remediate with IBM Bob
            </button>
            {briefOpen && (
              <div
                role="dialog"
                aria-labelledby={`ibm-bob-brief-title-${finding.id}`}
                style={{
                  marginBottom: "14px",
                  padding: "16px",
                  background: "var(--sd-surface)",
                  border: "1px solid var(--sd-border-2)",
                  borderRadius: "var(--sd-radius-sm)",
                }}
              >
                <h3
                  id={`ibm-bob-brief-title-${finding.id}`}
                  style={{ margin: "0 0 10px", color: "var(--sd-text)", fontSize: "15px" }}
                >
                  IBM Bob Remediation Brief
                </h3>
                <pre
                  style={{
                    margin: 0,
                    color: "var(--sd-text-dim)",
                    fontFamily: "var(--sd-mono)",
                    fontSize: "12px",
                    lineHeight: 1.6,
                    whiteSpace: "pre-wrap",
                    overflowWrap: "anywhere",
                    userSelect: "text",
                  }}
                >
                  {remediationBrief}
                </pre>
                <p role="status" style={{ minHeight: "18px", margin: "8px 0", color: "var(--sd-text-muted)", fontSize: "12px" }}>
                  {copyMessage || "Copy this brief into IBM Bob. No files are changed and Bob is not called."}
                </p>
                <div style={{ display: "flex", gap: "8px" }}>
                  <button type="button" onClick={handleCopyBrief}>Copy Brief</button>
                  <button type="button" onClick={() => setBriefOpen(false)}>Close</button>
                </div>
              </div>
            )}
            <div className="inv-verify-row">
              <span className="inv-verify-icon" aria-hidden="true">
                {finding.status === "FIXED" ? "✓" : "○"}
              </span>
              <span className="inv-verify-text">
                {finding.remediation
                  ? finding.remediation
                  : finding.status === "FIXED"
                  ? "Fix applied · Tested · Baseline rule now satisfied"
                  : "Awaiting remediation"}
                {" "}·{" "}
                <StatusBadge type="status" value={finding.status} />
              </span>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
