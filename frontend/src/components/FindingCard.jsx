import { useState } from "react";
import StatusBadge from "./StatusBadge";

// FindingCard — collapsible card showing the full investigation flow for a single drift finding.
// Expanded body follows: Pattern → Detection → Why it's drift → Evidence → Remediation
export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`finding-card${expanded ? " finding-card--open" : ""}`}>

      {/* ── Header row ─────────────────────────────────────────────── */}
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

      {/* ── Expanded investigation body ─────────────────────────────── */}
      {expanded && (
        <div className="finding-body">

          {/* A. Repository pattern */}
          <div className="inv-section">
            <div className="inv-label inv-label--pattern">
              <span className="inv-step" aria-hidden="true">A</span>
              Established repository pattern
            </div>
            <p className="inv-text">{finding.repositoryPattern}</p>
          </div>

          {/* B. Detected implementation */}
          <div className="inv-section">
            <div className="inv-label inv-label--detected">
              <span className="inv-step" aria-hidden="true">B</span>
              Detected implementation
            </div>
            <p className="inv-text">{finding.detectedImplementation}</p>
            <div className="inv-location">
              <span className="inv-loc-label">Location</span>
              <code className="inv-loc-value">{finding.location}</code>
            </div>
          </div>

          {/* C. Why this is classified as drift */}
          <div className="inv-section inv-section--drift">
            <div className="inv-label inv-label--drift">
              <span className="inv-step" aria-hidden="true">C</span>
              Why this is classified as security drift
            </div>
            <p className="inv-text">{finding.driftReason}</p>
            <div className="inv-verdict">
              <span className="inv-loc-label">Verdict</span>
              <span className="inv-verdict-text">{finding.verdict}</span>
            </div>
          </div>

          {/* D. Code evidence: before → after */}
          <div className="inv-section">
            <div className="inv-label inv-label--evidence">
              <span className="inv-step" aria-hidden="true">D</span>
              Code evidence
            </div>
            <div className="before-after">
              <div className="ba-panel ba-before">
                <div className="ba-label">Before</div>
                <p className="ba-description">{finding.before.label}</p>
                <pre className="ba-code">{finding.before.code}</pre>
                <p className="ba-impact">{finding.before.impact}</p>
              </div>
              <div className="ba-panel ba-after">
                <div className="ba-label">After</div>
                <p className="ba-description">{finding.after.label}</p>
                <pre className="ba-code">{finding.after.code}</pre>
                <p className="ba-property">{finding.after.property}</p>
              </div>
            </div>
          </div>

          {/* E. Verification result */}
          <div className="inv-section inv-section--verified">
            <div className="inv-label inv-label--verified">
              <span className="inv-step" aria-hidden="true">E</span>
              Remediation &amp; verification
            </div>
            <div className="inv-verify-row">
              <span className="inv-verify-icon" aria-hidden="true">✓</span>
              <span className="inv-verify-text">
                Fix applied · Tested · Baseline rule now satisfied ·{" "}
                <StatusBadge type="status" value="FIXED" />
              </span>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
