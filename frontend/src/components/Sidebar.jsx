import { NavLink } from "react-router-dom";
import { DashboardIcon, TerminalIcon, LogIcon, FileIcon, UploadIcon, ShareIcon, LockIcon } from "./Icons";

function Sidebar() {
  return (
    <aside className="sidebar">
      <div>
        <div className="sidebar-title">
          Security Suite
        </div>

        <nav className="sidebar-menu">
          <NavLink to="/dashboard" className={({ isActive }) => (isActive ? "active" : "")}>
            <DashboardIcon size={18} />
            <span>Dashboard</span>
          </NavLink>

          <NavLink to="/simulator" className={({ isActive }) => (isActive ? "active" : "")}>
            <TerminalIcon size={18} />
            <span>Attack Simulator</span>
          </NavLink>

          <NavLink to="/logs" className={({ isActive }) => (isActive ? "active" : "")}>
            <LogIcon size={18} />
            <span>Attack Logs</span>
          </NavLink>

          <div style={{ height: "1px", background: "var(--border-subtle)", margin: "12px 0" }} />

          <NavLink to="/files" className={({ isActive }) => (isActive ? "active" : "")}>
            <FileIcon size={18} />
            <span>Encrypted Vault</span>
          </NavLink>

          <NavLink to="/upload" className={({ isActive }) => (isActive ? "active" : "")}>
            <UploadIcon size={18} />
            <span>Upload & Encrypt</span>
          </NavLink>

          <NavLink to="/shared" className={({ isActive }) => (isActive ? "active" : "")}>
            <ShareIcon size={18} />
            <span>Shared Links</span>
          </NavLink>
        </nav>
      </div>

      <div className="sidebar-footer">
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
          <LockIcon size={14} color="var(--accent-primary)" />
          <strong>AES-256-GCM Vault</strong>
        </div>
        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
          Authenticated cryptographic storage with live sliding-window SIEM telemetry.
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;