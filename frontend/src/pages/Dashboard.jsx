import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import StatusBadge from "../components/StatusBadge";
import FindingCard from "../components/FindingCard";
import {
  REPO,
  BASELINE,
  FINDINGS,
  VERIFICATION,
  WORKFLOW_STEPS,
} from "../data/findings";

// ── Analyse simulation ───────────────────────────────────────────────────────
// Three phases the button cycles through.
const ANALYSIS_PHASES = [
  "Reading SECURITY_PATTERNS.md…",
  "Scanning authentication routes…",
  "Comparing password-reset flow against baseline…",
  "Validating token generation and storage…",
  "Checking error-message patterns…",
  "Compiling findings…",
  "Analysis complete",
];

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
  const [phaseIndex, setPhaseIndex] = useState(-1);
  const [done, setDone] = useState(false);

  function handleAnalyse() {
    if (analysing) return;
    setDone(false);
    setAnalysing(true);
    setPhaseIndex(0);
  }

  useEffect(() => {
    if (!analysing) return;
    if (phaseIndex >= ANALYSIS_PHASES.length - 1) {
      setAnalysing(false);
      setDone(true);
      return;
    }
    const t = setTimeout(() => setPhaseIndex((i) => i + 1), 520);
    return () => clearTimeout(t);
  }, [analysing, phaseIndex]);

  function handleLogout() {
    localStorage.removeItem("token");
    navigate("/");
  }

  const pct = Math.round((BASELINE.satisfiedRules / BASELINE.totalRules) * 100);

  return (
    <div className="sd-page">

      {/* ── Top navigation ──────────────────────────────────────────── */}
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

        {/* ── Page heading ──────────────────────────────────────────── */}
        <section className="sd-hero">
          <p className="sd-hero-eyebrow">Developer Security</p>
          <h1 className="sd-hero-title">Security Drift</h1>
          <p className="sd-hero-sub">
            Security is often checked after code ships.&nbsp;
            <strong>Security Drift</strong> brings it into your development workflow —
            comparing every change against your repository's established security baseline
            and surfacing deviations before they become vulnerabilities.
          </p>
        </section>

        {/* ── Repository status card ────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Repository Status</h2>
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
                  <StatusBadge type="status" value="FIXED" />
                  <span className="sd-status-detail">Analysis complete · All drift remediated</span>
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Analyse button ────────────────────────────────────────── */}
        <section className="sd-section sd-analyse-section">
          <button
            className={`sd-analyse-btn${analysing ? " sd-analyse-btn--busy" : ""}`}
            onClick={handleAnalyse}
            disabled={analysing}
          >
            {analysing ? "Analysing…" : "Analyze Repository"}
          </button>

          {(analysing || done) && (
            <div className="sd-progress">
              {ANALYSIS_PHASES.slice(0, analysing ? phaseIndex + 1 : ANALYSIS_PHASES.length).map(
                (phase, i) => (
                  <div
                    key={i}
                    className={`sd-progress-line${
                      i === phaseIndex && analysing ? " sd-progress-line--active" : ""
                    }${i < (analysing ? phaseIndex : ANALYSIS_PHASES.length) ? " sd-progress-line--done" : ""}`}
                  >
                    <span className="sd-progress-icon" aria-hidden="true">
                      {i === phaseIndex && analysing ? "◌" : "✓"}
                    </span>
                    {phase}
                  </div>
                )
              )}
              {done && (
                <p className="sd-progress-result">
                  Repository aligned with baseline. 0 confirmed drift findings remaining.
                </p>
              )}
            </div>
          )}

          <p className="sd-analyse-note">
            This simulation reflects the completed Phase 1 analysis of this repository.
            Live analysis connects to your backend when available.
          </p>
        </section>

        {/* ── Baseline compliance ───────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Security Baseline</h2>
          <p className="sd-section-sub">
            Sourced from <code className="sd-inline-code">{BASELINE.file}</code> · Current verified state
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

        {/* ── Drift findings ────────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Drift Findings</h2>
          <p className="sd-section-sub">
            4 confirmed findings identified · 4 remediated · 0 remaining
          </p>

          <div className="sd-findings-list">
            {FINDINGS.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>

          <div className="sd-out-of-scope">
            <span className="sd-oos-label">Out of scope</span>
            {VERIFICATION.outOfScopeFindings.map((f) => (
              <span key={f.id} className="sd-oos-item">
                <StatusBadge type="status" value="OUT OF SCOPE" />
                <span className="sd-oos-id">{f.id}</span>
                <span className="sd-oos-reason">{f.reason}</span>
              </span>
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

        {/* ── How it works ──────────────────────────────────────────── */}
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
        <p>Security Drift · Phase 1 analysis complete · Repository aligned with baseline</p>
      </footer>
    </div>
  );
}
