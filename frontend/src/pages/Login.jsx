import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

function Login() {
  const [email, setEmail] = useState("admin@secureshare.local");
  const [password, setPassword] = useState("Admin@123456");
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (email && password) {
      setLoading(true);
      const username = email.split("@")[0] || "admin";
      localStorage.setItem("secureshare_user", username);
      localStorage.setItem("secureshare_email", email);
      setTimeout(() => {
        setLoading(false);
        navigate("/dashboard");
      }, 300);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <h1>🛡️ SecureShare</h1>
        <h2>Cybersecurity Portal</h2>
        <p>Enterprise AES-256 File Vault & SIEM Threat Detection</p>

        <form onSubmit={handleLogin}>
          <div>
            <label>Email or Username</label>
            <input
              type="text"
              placeholder="e.g. admin@secureshare.local"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div>
            <label>Password</label>
            <input
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          <button type="submit" disabled={loading}>
            {loading ? "Authenticating..." : "Sign In to SecureShare"}
          </button>
        </form>

        <p className="auth-link">
          Don't have an account? <Link to="/register">Register here</Link>
        </p>

        <div style={{ marginTop: "20px", padding: "12px", background: "rgba(59, 130, 246, 0.08)", border: "1px solid rgba(59, 130, 246, 0.2)", borderRadius: "10px", fontSize: "12px", color: "var(--text-secondary)", textAlign: "center" }}>
          Default Test Account: <strong style={{ color: "#fff" }}>admin</strong> / <strong style={{ color: "#fff" }}>Admin@123456</strong>
        </div>
      </div>
    </div>
  );
}

export default Login;