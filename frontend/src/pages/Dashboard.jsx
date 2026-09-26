import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import FindingCard from "../components/FindingCard";
import StatusBadge from "../components/StatusBadge";

const API_URL = "http://localhost:5000/api/analysis";

function findingSummary(finding) {
  const title = finding.title.toLowerCase();

  if (title.includes("account enumeration")) {
    return "The password reset response could reveal whether an email address has an account.";
  }
  if (title.includes("exposed") && title.includes("token")) {
    return "A password reset token may be visible in an API response.";
  }
  if (title.includes("plaintext") || title.includes("token stored")) {
    return "A password reset token is stored without the protection used for other credentials.";
  }
  if (title.includes("token generation") || title.includes("random")) {
    return "The password reset token may be generated in a way that is easier to guess.";
  }

  return "This change handles a security concern differently from practices already used in this project.";
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

  // ── Live analysis result from the API ─────────────────────────────────
  const [result, setResult] = useState(null);

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

  const summary = result?.summary || {};
  const meta = result?.meta || {};
  const confirmedDrift  = result?.confirmedDrift || [];
  const driftCount = summary.confirmedDrift ?? confirmedDrift.length;

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
          <h1 className="sd-hero-title">Security Drift</h1>
          <p className="sd-hero-sub">
            Find security changes that don't match your project's existing security practices.
          </p>
        </section>

        {/* ── Analyze Repository ──────────────────────────────────────── */}
        <section className="sd-section">
          <div className="sd-analyse-card">

            {/* Path input + button row */}
            <div className="sd-analyse-input-row">
              <div className="sd-field sd-analyse-path-field">
                <label className="sd-label" htmlFor="repo-path-input">
                  Repository Path
                </label>
                <input
                  id="repo-path-input"
                  className="sd-input"
                  type="text"
                  placeholder="C:\\path\\to\\your\\repository"
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

            {uiState === "analysing" && (
              <p className="sd-analysis-status" role="status">Analyzing repository…</p>
            )}

          </div>
        </section>

        {/* ── Results — only shown after a successful analysis ───────── */}
        {uiState === "done" && result && (
          <>
            <section className="sd-section">
              <div className="sd-result-summary">
                <h2 className={driftCount > 0 ? "sd-result-status sd-result-status--drift" : "sd-result-status"}>
                  {driftCount > 0 ? "Security Drifts Found" : "No Security Drift Found"}
                </h2>
                <div className="sd-result-counts">
                  <div className="sd-result-count">
                    <strong>{meta.filesScanned ?? 0}</strong>
                    <span>Files scanned</span>
                  </div>
                  <div className="sd-result-count">
                    <strong>{driftCount}</strong>
                    <span>Security drifts found</span>
                  </div>
                </div>
              </div>

              {confirmedDrift.length > 0 && (
                <div className="sd-findings-list">
                  {confirmedDrift.map((finding) => (
                    <article className="sd-finding-item" key={finding.id}>
                      <div className="sd-finding-severity">
                        <StatusBadge type="severity" value={finding.severity} />
                      </div>
                      <h3 className="sd-finding-title">{finding.title}</h3>
                      <p className="sd-finding-explanation">{findingSummary(finding)}</p>
                      <p className="sd-finding-location">{finding.file}</p>
                      <FindingCard finding={finding} />
                    </article>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        {/* ── How it works — always visible ──────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title sd-how-title">How it works</h2>
          <p className="sd-how-flow">Detect <span aria-hidden="true">→</span> Explain <span aria-hidden="true">→</span> Fix with IBM Bob <span aria-hidden="true">→</span> Verify</p>
        </section>

      </main>

    </div>
  );
}
