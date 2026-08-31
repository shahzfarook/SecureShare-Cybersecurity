import { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

function Dashboard() {
  const [fileStats, setFileStats] = useState({ total_files: 0, total_plain_size_bytes: 0, total_encrypted_size_bytes: 0 });
  const [threatStats, setThreatStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentFiles, setRecentFiles] = useState([]);

  const fetchDashboardData = async () => {
    // 1. Fetch File Storage Stats (Port 8001)
    try {
      const fileRes = await axios.get("http://localhost:8001/api/files/stats");
      setFileStats(fileRes.data);
    } catch (e) {
      console.log("Files API offline or unreachable:", e.message);
    }

    // 2. Fetch File List for recent activity
    try {
      const listRes = await axios.get("http://localhost:8001/api/files/list");
      setRecentFiles(listRes.data.slice(0, 5));
    } catch (e) {
      console.log("Files list offline:", e.message);
    }

    // 3. Fetch Threat Stats (Port 5000)
    try {
      const threatRes = await axios.get("http://localhost:5000/api/stats");
      setThreatStats(threatRes.data);
    } catch (e) {
      console.log("Log Analyzer API offline:", e.message);
    }

    // 4. Fetch Recent Security Alerts (Port 5000)
    try {
      const alertsRes = await axios.get("http://localhost:5000/api/alerts?limit=4");
      setRecentAlerts(alertsRes.data.alerts || []);
    } catch (e) {
      console.log("Alerts API offline:", e.message);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Cybersecurity Command Dashboard</h1>
          <p className="page-subtitle">Real-time status of encrypted file storage and threat detection SIEM</p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchDashboardData}>
            🔄 Refresh Metrics
          </button>
          <Link to="/upload" className="btn-primary">
            + Encrypt & Upload
          </Link>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(59, 130, 246, 0.15)", borderColor: "rgba(59, 130, 246, 0.3)" }}>
            📁
          </div>
          <div>
            <div className="stat-value">{fileStats.total_files || 0}</div>
            <div className="stat-label">Encrypted Files at Rest</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(6, 182, 212, 0.15)", borderColor: "rgba(6, 182, 212, 0.3)" }}>
            🔒
          </div>
          <div>
            <div className="stat-value">
              {((fileStats.total_plain_size_bytes || 0) / 1024).toFixed(1)} KB
            </div>
            <div className="stat-label">AES-256 Vault Size</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(239, 68, 68, 0.15)", borderColor: "rgba(239, 68, 68, 0.3)" }}>
            🛡️
          </div>
          <div>
            <div className="stat-value" style={{ color: recentAlerts.length > 0 ? "var(--accent-red)" : "var(--accent-green)" }}>
              {threatStats?.summary?.total_threat_alerts ?? recentAlerts.length}
            </div>
            <div className="stat-label">Security Alerts Detected</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(16, 185, 129, 0.15)", borderColor: "rgba(16, 185, 129, 0.3)" }}>
            ⚡
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-green)" }}>
              {threatStats?.summary?.total_requests_analyzed ?? 0}
            </div>
            <div className="stat-label">Access Logs Analyzed</div>
          </div>
        </div>
      </div>

      {/* Security Threat Alerts Feed */}
      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>🚨</span>
            <span>Real-Time Security Alerts (Log Analyzer Engine)</span>
          </div>
          <Link to="/activity" className="btn-secondary" style={{ fontSize: "12px" }}>
            View Full SIEM Logs →
          </Link>
        </div>

        {recentAlerts.length === 0 ? (
          <div style={{ padding: "24px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: "12px", display: "flex", alignItems: "center", gap: "14px" }}>
            <span style={{ fontSize: "24px" }}>✅</span>
            <div>
              <div style={{ fontWeight: "700", color: "var(--accent-green)" }}>System Status: Operational & Secure</div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "2px" }}>
                No active brute-force attacks, SQL injection attempts, or credential stuffing anomalies detected.
              </div>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                style={{
                  padding: "16px 20px",
                  background: "rgba(17, 24, 39, 0.8)",
                  border: "1px solid rgba(239, 68, 68, 0.3)",
                  borderRadius: "12px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "4px" }}>
                    <span
                      className={`badge-tag ${
                        alert.severity === "CRITICAL"
                          ? "badge-critical"
                          : alert.severity === "HIGH"
                          ? "badge-high"
                          : "badge-medium"
                      }`}
                    >
                      {alert.severity}
                    </span>
                    <strong style={{ color: "#fff", fontSize: "14px" }}>{alert.alert_type}</strong>
                    <span className="hash-cell" style={{ fontSize: "11px" }}>IP: {alert.ip}</span>
                  </div>
                  <div style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                    {alert.message}
                  </div>
                </div>

                <div style={{ textAlign: "right", fontSize: "12px", color: "var(--text-muted)" }}>
                  <div>Target: <strong style={{ color: "#fff" }}>{alert.target_user}</strong></div>
                  <div>Attempts: {alert.count}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Files Vault Section */}
      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>🗄️</span>
            <span>Recently Encrypted Files</span>
          </div>
          <Link to="/files" className="btn-secondary" style={{ fontSize: "12px" }}>
            Open Vault →
          </Link>
        </div>

        {recentFiles.length === 0 ? (
          <div style={{ textAlign: "center", padding: "28px", color: "var(--text-secondary)" }}>
            No files uploaded yet. Upload your first confidential file to encrypt with AES-256.
          </div>
        ) : (
          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Encryption Standard</th>
                  <th>Plaintext Size</th>
                  <th>SHA-256 Hash</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentFiles.map((file) => (
                  <tr key={file.file_id}>
                    <td style={{ fontWeight: "600", color: "#fff" }}>📄 {file.filename}</td>
                    <td>
                      <span className="badge-tag badge-success">{file.encryption_algorithm || "AES-256-GCM"}</span>
                    </td>
                    <td>{(file.file_size / 1024).toFixed(1)} KB</td>
                    <td className="hash-cell" style={{ fontSize: "11px" }}>
                      {file.sha256_hash ? `${file.sha256_hash.slice(0, 16)}...` : "-"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <a
                        href={`http://localhost:8001/api/files/download/${file.file_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="btn-secondary"
                        style={{ textDecoration: "none", fontSize: "12px", padding: "6px 12px" }}
                      >
                        ⬇️ Download
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;