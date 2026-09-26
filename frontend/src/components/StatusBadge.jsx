// StatusBadge — severity and status pill component.
// Accepts a `type` prop ("severity" | "status") and a `value` string.

const SEVERITY_STYLES = {
  CRITICAL: { bg: "#3d1515", color: "#f87171", border: "#7f1d1d" },
  HIGH:     { bg: "#3d2a10", color: "#fb923c", border: "#7c3a0e" },
  MEDIUM:   { bg: "#362d08", color: "#facc15", border: "#713f12" },
  LOW:      { bg: "#0d2b3e", color: "#60a5fa", border: "#1e3a5f" },
};

const STATUS_STYLES = {
  FIXED:          { bg: "#0d2e1e", color: "#4ade80", border: "#166534" },
  OPEN:           { bg: "#3d1515", color: "#f87171", border: "#7f1d1d" },
  "IN PROGRESS":  { bg: "#1e2a3a", color: "#93c5fd", border: "#1d4ed8" },
  CONFIRMED:      { bg: "#3d2a10", color: "#fb923c", border: "#7c3a0e" },
  "OUT OF SCOPE": { bg: "#1a1f2e", color: "#94a3b8", border: "#334155" },
};

export default function StatusBadge({ type = "severity", value }) {
  const map = type === "status" ? STATUS_STYLES : SEVERITY_STYLES;
  const style = map[value] || { bg: "#1a1f2e", color: "#94a3b8", border: "#334155" };

  return (
    <span
      style={{
        display: "inline-block",
        fontSize: "11px",
        fontWeight: 700,
        letterSpacing: "0.06em",
        textTransform: "uppercase",
        padding: "2px 9px",
        borderRadius: "12px",
        backgroundColor: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
        whiteSpace: "nowrap",
        lineHeight: "1.8",
      }}
    >
      {value}
    </span>
  );
}
