import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import FindingCard from "../components/FindingCard";
import {
  REPO,
  BASELINE,
  FINDINGS,
  EXCLUDED_FINDINGS,
  VERIFICATION,
  ANALYSIS_TIMELINE,
  WORKFLOW_STEPS,
} from "../data/findings";

// ── Analysis simulation steps ─────────────────────────────────────────────
// Each step maps to a phase of the Detect → Validate → Remediate → Verify flow.
const ANALYSIS_STEPS = [
  { phase: "detect",    text: "Reading SECURITY_PATTERNS.md baseline…" },
  { phase: "detect",    text: "Scanning authentication routes…" },
  { phase: "detect",    text: "Scanning password-reset flow…" },
  { phase: "validate",  text: "Comparing implementations against baseline patterns…" },
  { phase: "validate",  text: "Classifying deviations: drift vs gap vs intentional…" },
  { phase: "remediate", text: "Reviewing applied fixes…" },
  { phase: "verify",    text: "Checking baseline rule compliance…" },
  { phase: "verify",    text: "Verifying test suite results…" },
];

const PHASE_LABEL = {
  detect:    "Detect",
  validate:  "Validate",
  remediate: "Remediate",
  verify:    "Verify",
};

export default function Dashboard() {
  const navigate = useNavigate();

  // Auth guard — consistent with Profile.jsx pattern.
  useEffect(() => {
    if (!localStorage.getItem("token")) {
      navigate("/");
    }
  }, [navigate]);

  // Analysis simulation state.
  const [analysing, setAnalysing] = useState(false);
  const [stepIndex, setStepIndex] = useState(-1);
  const [done, setDone] = useState(false);

  function handleAnalyse() {
    if (analysing) return;
    setDone(false);
    setAnalysing(true);
    setStepIndex(0);
  }

  useEffect(() => {
    if (!analysing) return;
    if (stepIndex >= ANALYSIS_STEPS.length - 1) {
      setAnalysing(false);
      setDone(true);
      return;
    }
    const t = setTimeout(() => setStepIndex((i) => i + 1), 480);
    return () => clearTimeout(t);
  }, [analysing, stepIndex]);

  function handleLogout() {
    localStorage.removeItem("token");
    navigate("/");
  }

  const pct = Math.round((BASELINE.satisfiedRules / BASELINE.totalRules) * 100);

  // Track which phase labels have appeared
  const visibleSteps = analysing
    ? ANALYSIS_STEPS.slice(0, stepIndex + 1)
    : done
    ? ANALYSIS_STEPS
    : [];

  return (
    <div className="sd-page">

      {/* ── Navigation ───────────────────────────────────────────────── */}
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

        {/* ── Hero ─────────────────────────────────────────────────────── */}
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

        {/* ── Repository status ─────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Repository</h2>
          <div className="sd-repo-card">
            <div className="sd-repo-grid">
              <div className="sd-repo-field">
                <span className="sd-field-label">Repository</span>
                <span className="sd-field-value sd-mono">{REPO.name}</span>
              </div>
              <div className="sd-repo-field">
                <span className="sd-field-label">Branch</span>
                <span className="sd-field-value sd-mono">{REPO.branch}</span>
              </div>
              <div className="sd-repo-field">
                <span className="sd-field-label">Baseline</span>
                <span className="sd-field-value sd-mono">{REPO.baseline}</span>
              </div>
              <div className="sd-repo-field">
                <span className="sd-field-label">Status</span>
                <span className="sd-field-value">
                  <span className="sd-aligned-badge">ALIGNED</span>
                  <span className="sd-status-detail">All confirmed drift remediated</span>
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Analysis timeline strip ───────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Latest Verified Analysis</h2>
          <p className="sd-section-sub">
            Completed analysis of this repository across the full Detect → Validate → Remediate → Verify workflow.
          </p>
          <div className="sd-timeline">
            {ANALYSIS_TIMELINE.map((stage, i) => (
              <div key={stage.stage} className="sd-tl-item">
                <div className="sd-tl-connector-wrap">
                  <div className="sd-tl-dot" />
                  {i < ANALYSIS_TIMELINE.length - 1 && (
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

        {/* ── Analyze Repository ────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Analyze Repository</h2>
          <p className="sd-section-sub">
            Runs the full Security Drift workflow: detect potential deviations, validate against
            the repository baseline, confirm drift, and verify current state.
          </p>

          <div className="sd-analyse-card">
            <div className="sd-analyse-top">
              <button
                className={`sd-analyse-btn${analysing ? " sd-analyse-btn--busy" : ""}`}
                onClick={handleAnalyse}
                disabled={analysing}
              >
                {analysing ? "Analysing…" : "Analyze Repository"}
              </button>
              <span className="sd-demo-badge">DEMO</span>
            </div>

            {/* Progress output */}
            {(analysing || done) && (
              <div className="sd-progress">
                <div className="sd-progress-phases">
                  {(["detect","validate","remediate","verify"]).map((phase) => {
                    const steps = visibleSteps.filter((s) => s.phase === phase);
                    if (steps.length === 0) return null;
                    const isCurrentPhase =
                      analysing &&
                      visibleSteps[visibleSteps.length - 1]?.phase === phase;
                    return (
                      <div key={phase} className="sd-progress-phase-block">
                        <div className={`sd-progress-phase-label${isCurrentPhase ? " sd-progress-phase-label--active" : ""}`}>
                          {PHASE_LABEL[phase]}
                        </div>
                        {steps.map((s, i) => {
                          const isActive =
                            analysing &&
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

                {done && (
                  <div className="sd-progress-result-block">
                    <div className="sd-progress-result-title">Analysis complete</div>
                    <div className="sd-progress-results">
                      <span className="sd-pr-item">
                        <span className="sd-pr-num">7</span>
                        <span className="sd-pr-label">potential deviations considered</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className="sd-pr-num sd-pr-num--alert">4</span>
                        <span className="sd-pr-label">confirmed security drifts</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className="sd-pr-num sd-pr-num--muted">3</span>
                        <span className="sd-pr-label">excluded from drift classification</span>
                      </span>
                      <span className="sd-pr-divider" aria-hidden="true" />
                      <span className="sd-pr-item">
                        <span className="sd-pr-num sd-pr-num--zero">0</span>
                        <span className="sd-pr-label">confirmed drift remaining</span>
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}

            <p className="sd-analyse-note">
              Demo analysis based on the verified Phase 1 repository analysis.
              Live repository analysis is planned for the next phase.
            </p>
          </div>
        </section>

        {/* ── Security baseline ─────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Security Baseline</h2>
          <p className="sd-section-sub">
            Sourced from <code className="sd-inline-code">{BASELINE.file}</code>{" "}
            · Current verified state after remediation
          </p>

          <div className="sd-baseline-card">
            <div className="sd-baseline-summary">
              <div className="sd-baseline-score">
                <span className="sd-score-num">{BASELINE.satisfiedRules}</span>
                <span className="sd-score-denom">/ {BASELINE.totalRules}</span>
                <span className="sd-score-label">rules satisfied</span>
              </div>
              <div className="sd-baseline-bar-wrap">
                <div className="sd-baseline-bar">
                  <div
                    className="sd-baseline-bar-fill"
                    style={{ width: `${pct}%` }}
                    role="progressbar"
                    aria-valuenow={BASELINE.satisfiedRules}
                    aria-valuemax={BASELINE.totalRules}
                  />
                </div>
                <span className="sd-baseline-pct">{pct}%</span>
              </div>
            </div>

            <div className="sd-baseline-sections">
              {BASELINE.sections.map((s) => (
                <div key={s.name} className="sd-baseline-row">
                  <span className="sd-baseline-row-name">{s.name}</span>
                  <span className="sd-baseline-row-pills">
                    {Array.from({ length: s.rules }).map((_, i) => (
                      <span
                        key={i}
                        className={`sd-rule-dot${i < s.satisfied ? " sd-rule-dot--ok" : " sd-rule-dot--fail"}`}
                        title={i < s.satisfied ? "Satisfied" : "Violated"}
                      />
                    ))}
                  </span>
                  <span className="sd-baseline-row-count">
                    {s.satisfied}/{s.rules}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ── Confirmed drift findings ──────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Confirmed Drift Findings</h2>
          <p className="sd-section-sub">
            {VERIFICATION.confirmedFindings} confirmed · {VERIFICATION.remediatedFindings} remediated · {VERIFICATION.remainingDrift} remaining
          </p>

          <div className="sd-findings-list">
            {FINDINGS.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        </section>

        {/* ── Not classified as drift ───────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Not Classified as Security Drift</h2>
          <p className="sd-section-sub">
            These findings were considered but excluded from drift classification.
            Security Drift only flags deviations from patterns already established in
            the repository — not general security gaps or intentional design choices.
          </p>

          <div className="sd-excluded-list">
            {EXCLUDED_FINDINGS.map((f) => (
              <div key={f.id} className="sd-excluded-card">
                <div className="sd-excluded-header">
                  <span className="sd-excluded-id">{f.id}</span>
                  <span className={`sd-excluded-category sd-excluded-category--${f.categoryStyle}`}>
                    {f.category}
                  </span>
                  <span className="sd-excluded-title">{f.title}</span>
                </div>
                <p className="sd-excluded-explanation">{f.explanation}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Verification summary ──────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Verification</h2>
          <p className="sd-section-sub">Post-remediation verification results</p>

          <div className="sd-verification-grid">
            <div className="sd-verify-card sd-verify-card--green">
              <span className="sd-verify-icon" aria-hidden="true">✓</span>
              <span className="sd-verify-num">{VERIFICATION.remediatedFindings}</span>
              <span className="sd-verify-label">Confirmed drifts remediated</span>
            </div>
            <div className="sd-verify-card sd-verify-card--green">
              <span className="sd-verify-icon" aria-hidden="true">✓</span>
              <span className="sd-verify-num">
                {VERIFICATION.baselineRulesSatisfied}/{VERIFICATION.baselineRulesTotal}
              </span>
              <span className="sd-verify-label">Baseline rules satisfied</span>
            </div>
            <div className="sd-verify-card sd-verify-card--green">
              <span className="sd-verify-icon" aria-hidden="true">✓</span>
              <span className="sd-verify-num">
                {VERIFICATION.testsPassing}/{VERIFICATION.testSuites}
              </span>
              <span className="sd-verify-label">Test suites passing</span>
            </div>
            <div className="sd-verify-card sd-verify-card--green">
              <span className="sd-verify-icon" aria-hidden="true">✓</span>
              <span className="sd-verify-num">{VERIFICATION.remainingDrift}</span>
              <span className="sd-verify-label">Confirmed drift remaining</span>
            </div>
          </div>
        </section>

        {/* ── How Security Drift works ──────────────────────────────── */}
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
        <p>Security Drift · Phase 1 complete · Repository aligned with baseline · 20/20 rules satisfied</p>
      </footer>
    </div>
  );
}
