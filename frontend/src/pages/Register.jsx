import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

function Register() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(null);

  const navigate = useNavigate();

  const handleRegister = (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }

    const username = name.toLowerCase().replace(/\s+/g, "_") || email.split("@")[0];
    localStorage.setItem("secureshare_user", username);
    localStorage.setItem("secureshare_email", email);

    navigate("/dashboard");
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>🛡️ SecureShare</h1>
        <h2>Create Account</h2>
        <p>Join SecureShare Enterprise Vault</p>

        {error && (
          <div style={{ marginBottom: "16px", padding: "10px 14px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", color: "#fca5a5", fontSize: "13px" }}>
            ⚠️ {error}
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

          <button type="submit">
            Create Account & Launch Dashboard
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