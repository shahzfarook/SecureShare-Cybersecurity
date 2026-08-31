import { useNavigate } from "react-router-dom";

function Navbar() {
  const navigate = useNavigate();
  const storedUser = localStorage.getItem("secureshare_user") || "Security Admin";

  const handleLogout = () => {
    localStorage.removeItem("secureshare_user");
    localStorage.removeItem("secureshare_token");
    navigate("/login");
  };

  return (
    <header className="navbar">
      <div className="navbar-logo">
        <span>🛡️</span>
        <span>SecureShare</span>
        <span className="badge">AES-256</span>
      </div>

      <div className="navbar-right">
        <div className="system-status">
          <span className="status-dot"></span>
          <span>Threat Engine: <strong>Active</strong></span>
        </div>

        <div className="user-pill">
          👤 {storedUser}
        </div>

        <button className="btn-logout" onClick={handleLogout}>
          Logout
        </button>
      </div>
    </header>
  );
}

export default Navbar;