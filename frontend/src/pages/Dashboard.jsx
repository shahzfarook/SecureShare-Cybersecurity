function Dashboard() {
  return (
    <div className="dashboard">
      <h1>Dashboard</h1>

      <p className="dashboard-subtitle">
        Welcome to your SecureShare workspace
      </p>

      <div className="stats-container">

        <div className="stat-card">
          <div className="stat-icon">📁</div>
          <div>
            <h3>My Files</h3>
            <p>0</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">👥</div>
          <div>
            <h3>Shared Files</h3>
            <p>0</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">📋</div>
          <div>
            <h3>Recent Activity</h3>
            <p>0</p>
          </div>
        </div>

      </div>

      <div className="recent-section">
        <h2>Recent Activity</h2>

        <div className="activity-box">
          <p>No recent activity</p>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;