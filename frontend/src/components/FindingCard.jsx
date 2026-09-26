import { useState } from "react";
import StatusBadge from "./StatusBadge";

// FindingCard — expands to show before → after evidence for a single finding.
export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="finding-card">
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

      {/* ── Expanded body ───────────────────────────────────────────── */}
      {expanded && (
        <div className="finding-body">
          <p className="finding-meta">
            <span className="meta-label">Location</span>
            <code>{finding.location}</code>
          </p>
          <p className="finding-meta">
            <span className="meta-label">Pattern violated</span>
            <span>{finding.patternViolated}</span>
          </p>
          <p className="finding-meta">
            <span className="meta-label">Verdict</span>
            <span>{finding.verdict}</span>
          </p>

          <div className="before-after">
            {/* BEFORE */}
            <div className="ba-panel ba-before">
              <div className="ba-label">Before</div>
              <p className="ba-description">{finding.before.label}</p>
              <pre className="ba-code">{finding.before.code}</pre>
              <p className="ba-impact">{finding.before.impact}</p>
            </div>

            {/* AFTER */}
            <div className="ba-panel ba-after">
              <div className="ba-label">After</div>
              <p className="ba-description">{finding.after.label}</p>
              <pre className="ba-code">{finding.after.code}</pre>
              <p className="ba-property">{finding.after.property}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
