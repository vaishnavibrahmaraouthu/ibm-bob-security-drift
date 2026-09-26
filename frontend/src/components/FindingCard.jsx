import { useState } from "react";
import StatusBadge from "./StatusBadge";

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
