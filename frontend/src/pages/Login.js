import React, { useState } from "react";
import { auth } from "../services/api";
import "./Login.css";

function formatApiError(err, fallback = "Authentication failed") {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const messages = detail.map((item) => item?.msg).filter(Boolean);
    if (messages.length > 0) return messages.join(", ");
  }
  return fallback;
}

export default function Login({ onLogin }) {
  const [isSignup, setIsSignup] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [company, setCompany] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      let res;
      if (isSignup) {
        res = await auth.signup({ email, password, full_name: fullName, company });
      } else {
        res = await auth.login(email, password);
      }
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("user_email", res.data.email);
      onLogin(res.data);
    } catch (e) {
      setError(formatApiError(e, "Authentication failed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">CloudTwin AI</div>
        <p className="login-sub">Cloud Security Compliance Platform</p>

        <div className="tab-row">
          <button className={`tab ${!isSignup ? "active" : ""}`} onClick={() => setIsSignup(false)}>Login</button>
          <button className={`tab ${isSignup ? "active" : ""}`} onClick={() => setIsSignup(true)}>Sign Up</button>
        </div>

        <form onSubmit={handleSubmit}>
          {isSignup && (
            <>
              <input placeholder="Full Name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
              <input placeholder="Company" value={company} onChange={(e) => setCompany(e.target.value)} />
            </>
          )}
          <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          {error && <div className="login-error">{error}</div>}
          <button type="submit" className="login-btn" disabled={loading}>
            {loading ? "Please wait..." : isSignup ? "Create Account" : "Login"}
          </button>
        </form>
      </div>
    </div>
  );
}
