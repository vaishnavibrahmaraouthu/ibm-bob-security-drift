import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import FindingCard from "../components/FindingCard";
import { WORKFLOW_STEPS } from "../data/findings";

const API_URL = "http://localhost:5000/api/analysis";

// ── Progress steps shown while the API call is in flight ──────────────────
const ANALYSIS_STEPS = [
  { phase: "detect",   text: "Reading SECURITY_PATTERNS.md baseline…" },
  { phase: "detect",   text: "Scanning authentication routes…" },
  { phase: "detect",   text: "Scanning password-reset flow…" },
  { phase: "validate", text: "Comparing implementations against baseline patterns…" },
  { phase: "validate", text: "Classifying deviations: drift vs gap vs intentional…" },
];

const PHASE_LABEL = {
  detect:    "Detect",
  validate:  "Validate",
  remediate: "Remediate",
  verify:    "Verify",
};

// ── Map API category value to the CSS modifier used by excluded cards ──────
function categoryStyle(category) {
  if (!category) return "gap";
  const c = category.toUpperCase();
  if (c.includes("INTENTIONAL")) return "intentional";
  if (c.includes("ARTIFACT") || c.includes("TEST")) return "artifact";
  return "gap";
}

// ── Derive a human-readable category label for the excluded badge ──────────
function categoryLabel(category) {
  if (!category) return "GENERAL GAP";
  const c = category.toUpperCase();
  if (c.includes("INTENTIONAL")) return "INTENTIONAL DESIGN";
  if (c.includes("ARTIFACT") || c.includes("TEST")) return "TEST ARTIFACT";
  if (c.includes("GAP")) return "GENERAL GAP";
  return category;
}

// ── Build the analysis-timeline rows from summary counts ──────────────────
function buildTimeline(summary, meta) {
  return [
    {
      stage: "Scan",
      label: "Scan",
      value: summary.potentialDeviations,
      unit:  "potential deviations",
      detail: `Scanned ${meta.filesScanned} file${meta.filesScanned !== 1 ? "s" : ""} against ${meta.baselineFile || "inferred baseline"}`,
    },
    {
      stage: "Validation",
      label: "Validate",
      value: summary.confirmedDrift,
      unit:  "confirmed security drifts",
      detail: "Each deviation checked: genuine drift vs intentional design vs general gap",
    },
    {
      stage: "Remediation",
      label: "Remediate",
      value: 0,
      unit:  "fixes applied",
      detail: "Remediation pending — use IBM Bob to apply targeted fixes",
    },
    {
      stage: "Verification",
      label: "Verify",
      value: summary.remainingDrift,
      unit:  "confirmed drift remaining",
      detail: summary.remainingDrift === 0
        ? "No confirmed drift after analysis"
        : `${summary.remainingDrift} confirmed drift finding${summary.remainingDrift !== 1 ? "s" : ""} open`,
    },
  ];
}

// ── Derive a simple baseline object from meta.baselineSections ────────────
// The API does not track "satisfied" per section, so we show total rules only.
function buildBaseline(meta) {
  const sections = (meta.baselineSections || []).map((s) => ({
    name:      s.name,
    rules:     s.rules,
    satisfied: s.rules, // assume all documented rules are the established baseline
  }));
  const totalRules = sections.reduce((n, s) => n + s.rules, 0);
  return {
    file:          meta.baselineFile || "SECURITY_PATTERNS.md",
    totalRules,
    satisfiedRules: totalRules,
    sections,
  };
}

// ─────────────────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();

  // Auth guard
  useEffect(() => {
    if (!localStorage.getItem("token")) {
      navigate("/");
    }
  }, [navigate]);

  // ── Repository path input ──────────────────────────────────────────────
  const [repoPath, setRepoPath] = useState("");

  // ── UI state machine: idle | analysing | done | error ─────────────────
  const [uiState, setUiState] = useState("idle"); // "idle"|"analysing"|"done"|"error"
  const [errorMsg, setErrorMsg] = useState("");

  // ── Animated progress step index (shown while analysing) ──────────────
  const [stepIndex, setStepIndex] = useState(-1);

  // ── Live analysis result from the API ─────────────────────────────────
  const [result, setResult] = useState(null);

  // Tick through progress steps while the API call is in flight
  useEffect(() => {
    if (uiState !== "analysing") return;
    if (stepIndex >= ANALYSIS_STEPS.length - 1) return;
    const t = setTimeout(() => setStepIndex((i) => i + 1), 480);
    return () => clearTimeout(t);
  }, [uiState, stepIndex]);

  // ── Handlers ──────────────────────────────────────────────────────────

  function handleLogout() {
    localStorage.removeItem("token");
    navigate("/");
  }

  async function handleAnalyse() {
    if (uiState === "analysing") return;
    if (!repoPath.trim()) {
      setErrorMsg("Please enter a repository path.");
      setUiState("error");
      return;
    }

    setUiState("analysing");
    setStepIndex(0);
    setErrorMsg("");
    setResult(null);

    try {
      const { data } = await axios.post(API_URL, { repositoryPath: repoPath.trim() });
      setResult(data);
      setUiState("done");
    } catch (err) {
      const msg =
        err?.response?.data?.message ||
        "Analysis failed. Check that the backend is running and the path is correct.";
      setErrorMsg(msg);
      setUiState("error");
    }
  }

  // ── Derived display values (only meaningful after a successful run) ────

  const summary  = result?.summary  || {};
  const meta     = result?.meta     || {};
  const baseline = result ? buildBaseline(meta) : null;
  const timeline = result ? buildTimeline(summary, meta) : null;

  const confirmedDrift  = result?.confirmedDrift || [];
  const excludedFindings = result?.excluded || [];

  const pct = baseline
    ? Math.round((baseline.satisfiedRules / (baseline.totalRules || 1)) * 100)
    : 0;

  // Progress log: visible steps while analysing or all steps when done
  const visibleSteps =
    uiState === "analysing"
      ? ANALYSIS_STEPS.slice(0, stepIndex + 1)
      : uiState === "done" || uiState === "error"
      ? ANALYSIS_STEPS
      : [];

  // Repo display name: last path segment or full path
  const repoDisplayName = meta.repoPath
    ? meta.repoPath.replace(/\\/g, "/").split("/").pop() || meta.repoPath
    : repoPath.replace(/\\/g, "/").split("/").pop() || "—";

  // Status badge: drift remaining?
  const hasDrift = summary.remainingDrift > 0;

  return (
    <div className="sd-page">

      {/* ── Navigation ──────────────────────────────────────────────── */}
      <header className="sd-nav">
        <div className="sd-nav-inner">
          <div className="sd-nav-brand">
            <span className="sd-nav-logo" aria-hidden="true">⬡</span>
            <span className="sd-nav-name">Security Drift</span>
          </div>
          <nav className="sd-nav-links">
            <a href="/profile" className="sd-nav-link">Profile</a>
            <button className="sd-nav-logout" onClick={handleLogout}>Logout</button>
          </nav>
        </div>
      </header>

      <main className="sd-main">

        {/* ── Hero ────────────────────────────────────────────────────── */}
        <section className="sd-hero">
          <p className="sd-hero-eyebrow">Developer Security</p>
          <h1 className="sd-hero-title">Security Drift</h1>
          <p className="sd-hero-sub">
            Security is often checked after code ships.{" "}
            <strong>Security Drift</strong> brings it into the development workflow —
            comparing new code against the security patterns already established in your
            repository, and surfacing deviations before they become vulnerabilities.
          </p>
        </section>

        {/* ── Analyze Repository ──────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Analyze Repository</h2>
          <p className="sd-section-sub">
            Enter a local repository path and run the full Security Drift workflow:
            detect potential deviations, validate against the repository baseline,
            confirm drift, and verify current state.
          </p>

          <div className="sd-analyse-card">

            {/* Path input + button row */}
            <div className="sd-analyse-input-row">
              <div className="sd-field sd-analyse-path-field">
                <label className="sd-label" htmlFor="repo-path-input">
                  Repository Path
                </label>
                <input
                  id="repo-path-input"
                  className="sd-input sd-mono"
                  type="text"
                  placeholder="e.g. C:\projects\my-repo or /home/user/my-repo"
                  value={repoPath}
                  onChange={(e) => setRepoPath(e.target.value)}
                  disabled={uiState === "analysing"}
                  onKeyDown={(e) => { if (e.key === "Enter") handleAnalyse(); }}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <button
                className={`sd-analyse-btn${uiState === "analysing" ? " sd-analyse-btn--busy" : ""}`}
                onClick={handleAnalyse}
                disabled={uiState === "analysing"}
              >
                {uiState === "analysing" ? "Analysing…" : "Analyze Repository"}
              </button>
            </div>

            {/* Error state */}
            {uiState === "error" && (
              <div className="sd-analyse-error" role="alert">
                {errorMsg}
              </div>
            )}

            {/* Progress log — shown while analysing and after completion */}
            {(uiState === "analysing" || uiState === "done" || uiState === "error") &&
              visibleSteps.length > 0 && (
              <div className="sd-progress">
                <div className="sd-progress-phases">
                  {["detect", "validate"].map((phase) => {
                    const steps = visibleSteps.filter((s) => s.phase === phase);
                    if (steps.length === 0) return null;
                    const isCurrentPhase =
                      uiState === "analysing" &&
                      visibleSteps[visibleSteps.length - 1]?.phase === phase;
                    return (
                      <div key={phase} className="sd-progress-phase-block">
                        <div className={`sd-progress-phase-label${isCurrentPhase ? " sd-progress-phase-label--active" : ""}`}>
                          {PHASE_LABEL[phase]}
                        </div>
                        {steps.map((s, i) => {
                          const isActive =
                            uiState === "analysing" &&
                            visibleSteps[visibleSteps.length - 1] === s;
                          return (
                            <div
                              key={i}
                              className={`sd-progress-line${isActive ? " sd-progress-line--active" : " sd-progress-line--done"}`}
                            >
                              <span className="sd-progress-icon" aria-hidden="true">
                                {isActive ? "◌" : "✓"}
                              </span>
                              {s.text}
                            </div>
                          );
                        })}
                      </div>
                    );
                  })}
                </div>

                {/* Result summary strip — shown after a successful run */}
                {uiState === "done" && result && (
                  <div className="sd-progress-result-block">
                    <div className="sd-progress-result-title">Analysis complete</div>
                    <div className="sd-progress-results">
                      <span className="sd-pr-item">
                        <span className="sd-pr-num">{summary.potentialDeviations}</span>
                        <span className="sd-pr-label">potential deviations considered</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className={`sd-pr-num${summary.confirmedDrift > 0 ? " sd-pr-num--alert" : ""}`}>
                          {summary.confirmedDrift}
                        </span>
                        <span className="sd-pr-label">confirmed security drifts</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className="sd-pr-num sd-pr-num--muted">{summary.excluded}</span>
                        <span className="sd-pr-label">excluded from drift classification</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className={`sd-pr-num${summary.remainingDrift === 0 ? " sd-pr-num--zero" : " sd-pr-num--alert"}`}>
                          {summary.remainingDrift}
                        </span>
                        <span className="sd-pr-label">confirmed drift remaining</span>
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}

          </div>
        </section>

        {/* ── Results sections — only shown after a successful analysis ── */}
        {uiState === "done" && result && (
          <>

            {/* ── Repository status ──────────────────────────────────── */}
            <section className="sd-section">
              <h2 className="sd-section-title">Repository</h2>
              <div className="sd-repo-card">
                <div className="sd-repo-grid">
                  <div className="sd-repo-field">
                    <span className="sd-field-label">Repository</span>
                    <span className="sd-field-value sd-mono">{repoDisplayName}</span>
                  </div>
                  <div className="sd-repo-field">
                    <span className="sd-field-label">Path</span>
                    <span className="sd-field-value sd-mono" style={{ fontSize: "11px", wordBreak: "break-all" }}>
                      {meta.repoPath}
                    </span>
                  </div>
                  <div className="sd-repo-field">
                    <span className="sd-field-label">Baseline</span>
                    <span className="sd-field-value sd-mono">
                      {meta.baselinePresent ? meta.baselineFile : "None — inferred"}
                    </span>
                  </div>
                  <div className="sd-repo-field">
                    <span className="sd-field-label">Status</span>
                    <span className="sd-field-value">
                      {hasDrift ? (
                        <>
                          <span className="sd-drift-badge">DRIFT DETECTED</span>
                          <span className="sd-status-detail">
                            {summary.remainingDrift} confirmed drift{summary.remainingDrift !== 1 ? "s" : ""} open
                          </span>
                        </>
                      ) : (
                        <>
                          <span className="sd-aligned-badge">ALIGNED</span>
                          <span className="sd-status-detail">No confirmed drift found</span>
                        </>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            </section>

            {/* ── Analysis timeline ───────────────────────────────────── */}
            <section className="sd-section">
              <h2 className="sd-section-title">Analysis Results</h2>
              <p className="sd-section-sub">
                Completed analysis across the full Detect → Validate → Remediate → Verify workflow.
                Analysed at {new Date(meta.analysedAt).toLocaleString()}.
              </p>
              <div className="sd-timeline">
                {timeline.map((stage, i) => (
                  <div key={stage.stage} className="sd-tl-item">
                    <div className="sd-tl-connector-wrap">
                      <div className="sd-tl-dot" />
                      {i < timeline.length - 1 && (
                        <div className="sd-tl-line" aria-hidden="true" />
                      )}
                    </div>
                    <div className="sd-tl-content">
                      <span className="sd-tl-stage">{stage.label}</span>
                      <span className={`sd-tl-value${stage.value === 0 ? " sd-tl-value--zero" : ""}`}>
                        {stage.value}
                      </span>
                      <span className="sd-tl-unit">{stage.unit}</span>
                      <span className="sd-tl-detail">{stage.detail}</span>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* ── Security Baseline ───────────────────────────────────── */}
            {baseline && baseline.sections.length > 0 && (
              <section className="sd-section">
                <h2 className="sd-section-title">Security Baseline</h2>
                <p className="sd-section-sub">
                  Sourced from{" "}
                  <code className="sd-inline-code">{baseline.file}</code>
                  {" "}· {baseline.totalRules} documented rules across {baseline.sections.length} categories
                </p>

                <div className="sd-baseline-card">
                  <div className="sd-baseline-summary">
                    <div className="sd-baseline-score">
                      <span className="sd-score-num">{baseline.satisfiedRules}</span>
                      <span className="sd-score-denom">/ {baseline.totalRules}</span>
                      <span className="sd-score-label">rules documented</span>
                    </div>
                    <div className="sd-baseline-bar-wrap">
                      <div className="sd-baseline-bar">
                        <div
                          className="sd-baseline-bar-fill"
                          style={{ width: `${pct}%` }}
                          role="progressbar"
                          aria-valuenow={baseline.satisfiedRules}
                          aria-valuemax={baseline.totalRules}
                        />
                      </div>
                      <span className="sd-baseline-pct">{pct}%</span>
                    </div>
                  </div>

                  <div className="sd-baseline-sections">
                    {baseline.sections.map((s) => (
                      <div key={s.name} className="sd-baseline-row">
                        <span className="sd-baseline-row-name">{s.name}</span>
                        <span className="sd-baseline-row-pills">
                          {Array.from({ length: s.rules }).map((_, i) => (
                            <span
                              key={i}
                              className="sd-rule-dot sd-rule-dot--ok"
                              title="Documented"
                            />
                          ))}
                        </span>
                        <span className="sd-baseline-row-count">
                          {s.rules} rule{s.rules !== 1 ? "s" : ""}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </section>
            )}

            {/* ── Confirmed drift findings ────────────────────────────── */}
            <section className="sd-section">
              <h2 className="sd-section-title">Confirmed Drift Findings</h2>
              <p className="sd-section-sub">
                {summary.confirmedDrift} confirmed · {summary.remainingDrift} remaining
              </p>

              {confirmedDrift.length === 0 ? (
                <div className="sd-empty-state">
                  No confirmed security drift found. The repository follows its established security patterns.
                </div>
              ) : (
                <div className="sd-findings-list">
                  {confirmedDrift.map((f) => (
                    <FindingCard key={f.id} finding={f} />
                  ))}
                </div>
              )}
            </section>

            {/* ── Not classified as drift ─────────────────────────────── */}
            {excludedFindings.length > 0 && (
              <section className="sd-section">
                <h2 className="sd-section-title">Not Classified as Security Drift</h2>
                <p className="sd-section-sub">
                  These findings were considered but excluded from drift classification.
                  Security Drift only flags deviations from patterns already established in
                  the repository — not general security gaps or intentional design choices.
                </p>

                <div className="sd-excluded-list">
                  {excludedFindings.map((f) => (
                    <div key={f.id} className="sd-excluded-card">
                      <div className="sd-excluded-header">
                        <span className="sd-excluded-id">{f.id}</span>
                        <span className={`sd-excluded-category sd-excluded-category--${categoryStyle(f.category)}`}>
                          {categoryLabel(f.category)}
                        </span>
                        <span className="sd-excluded-title">{f.title}</span>
                      </div>
                      <p className="sd-excluded-explanation">{f.classificationReason}</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* ── Verification summary ────────────────────────────────── */}
            <section className="sd-section">
              <h2 className="sd-section-title">Verification</h2>
              <p className="sd-section-sub">Analysis verification summary</p>

              <div className="sd-verification-grid">
                <div className={`sd-verify-card${summary.confirmedDrift > 0 ? " sd-verify-card--orange" : " sd-verify-card--green"}`}>
                  <span className="sd-verify-icon" aria-hidden="true">
                    {summary.confirmedDrift > 0 ? "!" : "✓"}
                  </span>
                  <span className="sd-verify-num">{summary.confirmedDrift}</span>
                  <span className="sd-verify-label">Confirmed drift findings</span>
                </div>
                <div className={`sd-verify-card${summary.remainingDrift > 0 ? " sd-verify-card--orange" : " sd-verify-card--green"}`}>
                  <span className="sd-verify-icon" aria-hidden="true">
                    {summary.remainingDrift > 0 ? "!" : "✓"}
                  </span>
                  <span className="sd-verify-num">{summary.remainingDrift}</span>
                  <span className="sd-verify-label">Confirmed drift remaining</span>
                </div>
                <div className="sd-verify-card sd-verify-card--green">
                  <span className="sd-verify-icon" aria-hidden="true">✓</span>
                  <span className="sd-verify-num">{summary.excluded}</span>
                  <span className="sd-verify-label">Findings excluded from drift</span>
                </div>
                <div className="sd-verify-card sd-verify-card--green">
                  <span className="sd-verify-icon" aria-hidden="true">✓</span>
                  <span className="sd-verify-num">{meta.filesScanned}</span>
                  <span className="sd-verify-label">Source files scanned</span>
                </div>
              </div>
            </section>

          </>
        )}

        {/* ── How Security Drift Works — always visible ───────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">How Security Drift Works</h2>
          <div className="sd-workflow">
            {WORKFLOW_STEPS.map((s, i) => (
              <div key={s.step} className="sd-workflow-item">
                <div className="sd-workflow-step">
                  <div className="sd-workflow-num">{s.step}</div>
                  {i < WORKFLOW_STEPS.length - 1 && (
                    <div className="sd-workflow-connector" aria-hidden="true" />
                  )}
                </div>
                <div className="sd-workflow-content">
                  <strong className="sd-workflow-label">{s.label}</strong>
                  <p className="sd-workflow-desc">{s.description}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

      </main>

      <footer className="sd-footer">
        <p>Security Drift · Local repository analysis · Powered by IBM Bob</p>
      </footer>
    </div>
  );
}
