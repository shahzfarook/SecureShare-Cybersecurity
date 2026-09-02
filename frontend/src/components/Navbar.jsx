import { useNavigate } from "react-router-dom";
import { ShieldIcon, LogoutIcon } from "./Icons";

function Navbar() {
  const navigate = useNavigate();
  const storedUser = localStorage.getItem("secureshare_user") || "admin";
  const userInitial = storedUser.charAt(0).toUpperCase();

  const handleLogout = () => {
    localStorage.removeItem("secureshare_user");
    localStorage.removeItem("secureshare_token");
    navigate("/login");
  };

  return (
    <header className="navbar">
      {/* Brand Identity */}
      <div className="navbar-logo">
        <div className="navbar-logo-emblem">
          <ShieldIcon size={20} color="#ffffff" />
        </div>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontWeight: "800", color: "var(--text-primary)", letterSpacing: "-0.5px" }}>Secure</span>
            <span style={{ fontWeight: "800", color: "var(--accent-primary)", letterSpacing: "-0.5px" }}>Share</span>
            <span className="badge">AES-256</span>
          </div>
        </div>
      </div>

      {/* Center Live SIEM Beacon */}
      <div className="navbar-center-telemetry">
        <div className="telemetry-pill">
          <span className="telemetry-beacon"></span>
          <span className="telemetry-text">
            SIEM Telemetry: <strong>Active Monitoring</strong>
          </span>
          <span className="telemetry-tag">Zero-Trust Vault</span>
        </div>
      </div>

      {/* Right User Capsule & Actions */}
      <div className="navbar-right">
        <div className="user-profile-card">
          <div className="user-avatar-bubble">
            {userInitial}
          </div>
          <div className="user-details-text">
            <span className="user-name">{storedUser}</span>
            <span className="user-role">Security Officer</span>
          </div>
        </div>

        <button className="btn-logout" onClick={handleLogout} title="Sign Out of Session">
          <LogoutIcon size={15} />
          <span>Sign Out</span>
        </button>
      </div>
    </header>
  );
}

export default Navbar;