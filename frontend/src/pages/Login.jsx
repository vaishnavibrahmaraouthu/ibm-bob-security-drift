import { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.post(
        "http://localhost:5000/api/auth/login",
        {
          email,
          password
        }
      );

      // Save JWT token
      localStorage.setItem("token", response.data.token);

      alert("Login successful");

      navigate("/profile");

    } catch (error) {
      alert(
        error.response?.data?.message || "Login failed"
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

        <h1 className="sd-auth-title">Welcome back</h1>
        <p className="sd-auth-sub">
          Sign in to your Security Drift workspace to review drift findings
          and baseline compliance for your repository.
        </p>

        <form className="sd-auth-form" onSubmit={handleLogin}>
          <div className="sd-field">
            <label className="sd-label" htmlFor="login-email">Email</label>
            <input
              id="login-email"
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
            <label className="sd-label" htmlFor="login-password">Password</label>
            <input
              id="login-password"
              className="sd-input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          <button type="submit" className="sd-btn-primary sd-btn-full">
            Sign in
          </button>
        </form>

        <p className="sd-auth-footer-link">
          Don&apos;t have an account?{" "}
          <a href="/register" className="sd-link">Create one</a>
        </p>

      </div>
    </div>
  );
}

export default Login;
