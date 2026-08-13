function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">
        SecureShare
      </div>

      <nav className="sidebar-menu">
        <a href="#">🏠 Dashboard</a>
        <a href="#">📁 My Files</a>
        <a href="#">⬆️ Upload File</a>
        <a href="#">👥 Shared Files</a>
        <a href="#">📋 Activity</a>
      </nav>
    </aside>
  );
}

export default Sidebar;