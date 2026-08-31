import { NavLink } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="sidebar">
      <div>
        <div className="sidebar-title">
          Cybersecurity Suite
        </div>

        <nav className="sidebar-menu">
          <NavLink to="/dashboard" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>🏠</span>
            <span>Dashboard</span>
          </NavLink>

          <NavLink to="/threats" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>🚨</span>
            <span>Threat Center</span>
          </NavLink>

          <NavLink to="/files" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>📁</span>
            <span>My Files</span>
          </NavLink>

          <NavLink to="/upload" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>⬆️</span>
            <span>Upload File</span>
          </NavLink>

          <NavLink to="/shared" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>👥</span>
            <span>Shared Files</span>
          </NavLink>

          <NavLink to="/activity" className={({ isActive }) => (isActive ? "active" : "")}>
            <span>📜</span>
            <span>SIEM Logs</span>
          </NavLink>
        </nav>
      </div>

      <div className="sidebar-footer">
        <div>🔒 <strong>AES-256-GCM Vault</strong></div>
        <div>🛡️ <strong>SHA-256 Digest</strong></div>
        <div>⚡ <strong>Real-Time SIEM</strong></div>
      </div>
    </aside>
  );
}

export default Sidebar;