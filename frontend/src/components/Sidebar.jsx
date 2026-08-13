import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="sidebar-title">
        SecureShare
      </div>

      <nav className="sidebar-menu">

        <Link to="/dashboard">
          🏠 Dashboard
        </Link>

        <Link to="/files">
          📁 My Files
        </Link>

        <Link to="/upload">
          ⬆️ Upload File
        </Link>

        <Link to="/shared">
          👥 Shared Files
        </Link>

        <Link to="/activity">
          📋 Activity
        </Link>

      </nav>

    </aside>
  );
}

export default Sidebar;