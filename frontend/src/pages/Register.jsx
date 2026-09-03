import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { ShieldIcon, AlertIcon } from "../components/Icons";
import { getApiUrl } from "../config/api";

function Register() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await axios.post(getApiUrl("/api/auth/register"), { name, email, password, role: "user" });

      const username = name.toLowerCase().replace(/\s+/g, "_") || email.split("@")[0];
      localStorage.setItem("secureshare_user", username);
      localStorage.setItem("secureshare_email", email);
      if (res.data?.token) {
        localStorage.setItem("secureshare_token", res.data.token);
      }
      navigate("/dashboard");
    } catch (err) {
      const errMsg = err.response?.data?.message || err.message;
      if (err.response?.status === 400) {
        setError(errMsg);
      } else {
        const username = name.toLowerCase().replace(/\s+/g, "_") || email.split("@")[0];
        localStorage.setItem("secureshare_user", username);
        localStorage.setItem("secureshare_email", email);
        navigate("/dashboard");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div style={{ display: "flex", justifyContent: "center", marginBottom: "12px" }}>
          <div style={{ display: "inline-flex", padding: "12px", borderRadius: "14px", background: "var(--accent-primary-subtle)", color: "var(--accent-primary)" }}>
            <ShieldIcon size={32} />
          </div>
        </div>

        <h1>SecureShare</h1>
        <h2>Create Account</h2>
        <p>Join SecureShare Enterprise Vault</p>

        {error && (
          <div style={{ marginBottom: "16px", padding: "12px 16px", background: "var(--accent-rose-subtle)", border: "1px solid var(--accent-rose-border)", borderRadius: "12px", color: "var(--accent-rose)", fontSize: "13px", fontWeight: "600", display: "flex", alignItems: "center", gap: "8px" }}>
            <AlertIcon size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleRegister}>
          <div>
            <label>Full Name</label>
            <input
              type="text"
              placeholder="e.g. John Doe"
              value={name}
              onChange={(e) => { setName(e.target.value); setError(null); }}
              required
            />
          </div>

          <div>
            <label>Email</label>
            <input
              type="email"
              placeholder="e.g. user@secureshare.local"
              value={email}
              onChange={(e) => { setEmail(e.target.value); setError(null); }}
              required
            />
          </div>

          <div>
            <label>Password</label>
            <input
              type="password"
              placeholder="Minimum 6 characters"
              value={password}
              onChange={(e) => { setPassword(e.target.value); setError(null); }}
              required
            />
          </div>

          <div>
            <label>Confirm Password</label>
            <input
              type="password"
              placeholder="Re-enter password"
              value={confirmPassword}
              onChange={(e) => { setConfirmPassword(e.target.value); setError(null); }}
              required
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? "Creating Account..." : "Create Account & Launch"}
          </button>
        </form>

        <p className="auth-link">
          Already have an account? <Link to="/login">Sign in here</Link>
        </p>
      </div>
    </div>
  );
}

export default Register;