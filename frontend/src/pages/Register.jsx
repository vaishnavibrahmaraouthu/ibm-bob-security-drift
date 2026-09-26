import { useState } from "react";
import axios from "axios";

function Register() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post(
        "http://localhost:5000/api/auth/register",
        {
          username,
          email,
          password
        }
      );

      alert(response.data.message);

    } catch (error) {
      alert(
        error.response?.data?.message || "Registration failed"
      );
    }
  };

  return (
    <div className="sd-page sd-auth-page">
      <div className="sd-auth-card">

        {/* Brand */}
        <div className="sd-auth-brand">
          <span className="sd-nav-logo" aria-hidden="true">⬡</span>
          <span className="sd-nav-name">Security Drift</span>
        </div>

        <h1 className="sd-auth-title">Create your account</h1>
        <p className="sd-auth-sub">
          Get started with Security Drift to detect and remediate security
          pattern deviations in your repositories.
        </p>

        <form className="sd-auth-form" onSubmit={handleRegister}>
          <div className="sd-field">
            <label className="sd-label" htmlFor="reg-username">Username</label>
            <input
              id="reg-username"
              className="sd-input"
              type="text"
              placeholder="your-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="sd-field">
            <label className="sd-label" htmlFor="reg-email">Email</label>
            <input
              id="reg-email"
              className="sd-input"
              type="email"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </div>

          <div className="sd-field">
            <label className="sd-label" htmlFor="reg-password">Password</label>
            <input
              id="reg-password"
              className="sd-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
            />
          </div>

          <button type="submit" className="sd-btn-primary sd-btn-full">
            Create account
          </button>
        </form>

        <p className="sd-auth-footer-link">
          Already have an account?{" "}
          <a href="/" className="sd-link">Sign in</a>
        </p>

      </div>
    </div>
  );
}

export default Register;
