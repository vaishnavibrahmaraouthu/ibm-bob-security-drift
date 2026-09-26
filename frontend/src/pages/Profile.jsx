import { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { REPO } from "../data/findings";

function Profile() {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/");
  };

  const [user, setUser] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchProfile = async () => {
      const token = localStorage.getItem("token");

      if (!token) {
        setError("You are not logged in");
        return;
      }

      try {
        const response = await axios.get(
          "http://localhost:5000/api/auth/profile",
          {
            headers: {
              Authorization: `Bearer ${token}`
            }
          }
        );

        setUser(response.data.user);

      } catch (error) {
        setError(
          error.response?.data?.message || "Failed to load profile"
        );
      }
    };

    fetchProfile();
  }, []);

  // ── Error / loading states ─────────────────────────────────────────────────
  if (error) {
    return (
      <div className="sd-page">
        <header className="sd-nav">
          <div className="sd-nav-inner">
            <div className="sd-nav-brand">
              <span className="sd-nav-logo" aria-hidden="true">⬡</span>
              <span className="sd-nav-name">Security Drift</span>
            </div>
          </div>
        </header>
        <main className="sd-main">
          <p className="sd-profile-error">{error}</p>
          <a href="/" className="sd-link">Return to sign in</a>
        </main>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="sd-page">
        <header className="sd-nav">
          <div className="sd-nav-inner">
            <div className="sd-nav-brand">
              <span className="sd-nav-logo" aria-hidden="true">⬡</span>
              <span className="sd-nav-name">Security Drift</span>
            </div>
          </div>
        </header>
        <main className="sd-main">
          <p className="sd-profile-loading">Loading…</p>
        </main>
      </div>
    );
  }

  // ── Profile initials for avatar ────────────────────────────────────────────
  const initials = user.username
    ? user.username.slice(0, 2).toUpperCase()
    : "??";

  return (
    <div className="sd-page">

      {/* ── Navigation ──────────────────────────────────────────────────── */}
      <header className="sd-nav">
        <div className="sd-nav-inner">
          <div className="sd-nav-brand">
            <span className="sd-nav-logo" aria-hidden="true">⬡</span>
            <span className="sd-nav-name">Security Drift</span>
          </div>
          <nav className="sd-nav-links">
            <a href="/dashboard" className="sd-nav-link">Dashboard</a>
            <button className="sd-nav-logout" onClick={handleLogout}>Logout</button>
          </nav>
        </div>
      </header>

      <main className="sd-main">

        {/* ── Page header ───────────────────────────────────────────────── */}
        <section className="sd-hero sd-hero--compact">
          <p className="sd-hero-eyebrow">Account</p>
          <h1 className="sd-hero-title">Profile</h1>
        </section>

        {/* ── Profile card ──────────────────────────────────────────────── */}
        <section className="sd-section">
          <h2 className="sd-section-title">Account Details</h2>
          <div className="sd-profile-card">
            <div className="sd-profile-avatar" aria-hidden="true">
              {initials}
            </div>
            <div className="sd-profile-fields">
              <div className="sd-repo-field">
                <span className="sd-field-label">Username</span>
                <span className="sd-field-value sd-mono">{user.username}</span>
              </div>
              <div className="sd-repo-field">
                <span className="sd-field-label">Email</span>
                <span className="sd-field-value sd-mono">{user.email}</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Workspace context card ────────────────────────────────────── */}
        {/* Presentation-only: uses existing REPO values already shown on Dashboard */}
        <section className="sd-section">
          <h2 className="sd-section-title">Workspace</h2>
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
                <span className="sd-field-label">State</span>
                <span className="sd-field-value">
                  <span>ANALYSIS AVAILABLE</span>
                  <span className="sd-status-detail">
                    Run Security Drift analysis from the Dashboard to see current findings.
                  </span>
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Actions ───────────────────────────────────────────────────── */}
        <section className="sd-section">
          <div className="sd-profile-actions">
            <a href="/dashboard" className="sd-btn-secondary">
              Go to Dashboard
            </a>
            <button className="sd-btn-danger" onClick={handleLogout}>
              Sign out
            </button>
          </div>
        </section>

      </main>

      <footer className="sd-footer">
        <p>Security Drift · {REPO.name} · {REPO.baseline}</p>
      </footer>
    </div>
  );
}

export default Profile;
