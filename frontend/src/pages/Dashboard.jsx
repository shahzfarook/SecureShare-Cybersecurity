import { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { ShieldIcon, LockIcon, FileIcon, RefreshIcon, UploadIcon, AlertIcon, DownloadIcon, TerminalIcon, LogIcon } from "../components/Icons";
import { getApiUrl } from "../config/api";

function Dashboard() {
  const [fileStats, setFileStats] = useState({ total_files: 0, total_plain_size_bytes: 0, total_encrypted_size_bytes: 0 });
  const [threatStats, setThreatStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [recentFiles, setRecentFiles] = useState([]);

  const fetchDashboardData = async () => {
    // 1. Fetch File Storage Stats
    try {
      const fileRes = await axios.get(getApiUrl("/api/files/stats"));
      setFileStats(fileRes.data || {});
    } catch (e) {
      console.log("Files API offline:", e.message);
    }

    // 2. Fetch File List for recent activity
    try {
      const listRes = await axios.get(getApiUrl("/api/files/list"));
      setRecentFiles((listRes.data || []).slice(0, 5));
    } catch (e) {
      console.log("Files list offline:", e.message);
    }

    // 3. Fetch Threat Stats
    try {
      const threatRes = await axios.get(getApiUrl("/api/stats"));
      setThreatStats(threatRes.data || {});
    } catch (e) {
      console.log("Log Analyzer API offline:", e.message);
    }

    // 4. Fetch Recent Security Alerts
    try {
      const alertsRes = await axios.get(getApiUrl("/api/alerts?limit=5"));
      const rawAlerts = alertsRes.data?.alerts || [];
      const sorted = [...rawAlerts].sort(
        (a, b) => new Date(b.last_seen || b.first_seen).getTime() - new Date(a.last_seen || a.first_seen).getTime()
      );
      setRecentAlerts(sorted);
    } catch (e) {
      console.log("Alerts API offline:", e.message);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 8000);
    return () => clearInterval(interval);
  }, []);

  const totalLogsAnalyzed = threatStats?.summary?.total_requests ?? threatStats?.summary?.total_requests_analyzed ?? 0;
  const totalAlertsCount = threatStats?.summary?.total_alerts ?? threatStats?.summary?.total_threat_alerts ?? recentAlerts.length;

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Executive Security Dashboard</h1>
          <p className="page-subtitle">Real-time telemetry for AES-256 encrypted file vault and SIEM threat engine</p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchDashboardData}>
            <RefreshIcon size={16} /> Refresh Metrics
          </button>
          <Link to="/upload" className="btn-primary">
            <UploadIcon size={16} /> Encrypt File
          </Link>
        </div>
      </div>

      {/* Key Metrics Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-primary-subtle)", borderColor: "rgba(126, 34, 206, 0.2)" }}>
            <FileIcon size={22} color="var(--accent-primary)" />
          </div>
          <div>
            <div className="stat-value">{fileStats.total_files || 0}</div>
            <div className="stat-label">Encrypted Files at Rest</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-amber-subtle)", borderColor: "var(--accent-amber-border)" }}>
            <LockIcon size={22} color="var(--accent-amber)" />
          </div>
          <div>
            <div className="stat-value">
              {((fileStats.total_plain_size_bytes || 0) / 1024).toFixed(1)} KB
            </div>
            <div className="stat-label">AES-256 Vault Size</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-rose-subtle)", borderColor: "var(--accent-rose-border)" }}>
            <AlertIcon size={22} color="var(--accent-rose)" />
          </div>
          <div>
            <div className="stat-value" style={{ color: totalAlertsCount > 0 ? "var(--accent-rose)" : "var(--accent-amber)" }}>
              {totalAlertsCount}
            </div>
            <div className="stat-label">Security Alerts Flagged</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-primary-subtle)", borderColor: "rgba(126, 34, 206, 0.2)" }}>
            <ShieldIcon size={22} color="var(--accent-primary)" />
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-primary)" }}>
              {totalLogsAnalyzed}
            </div>
            <div className="stat-label">Access Logs Analyzed</div>
          </div>
        </div>
      </div>

      {/* Security Threat Alerts Feed */}
      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>Real-Time Security Alerts</span>
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            <Link to="/simulator" className="btn-secondary" style={{ fontSize: "12px" }}>
              <TerminalIcon size={14} /> Attack Simulator
            </Link>
            <Link to="/logs" className="btn-secondary" style={{ fontSize: "12px" }}>
              <LogIcon size={14} /> View Attack Logs →
            </Link>
          </div>
        </div>

        {recentAlerts.length === 0 ? (
          <div style={{ padding: "26px", background: "var(--accent-amber-subtle)", border: "1px solid var(--accent-amber-border)", borderRadius: "16px", display: "flex", alignItems: "center", gap: "16px" }}>
            <ShieldIcon size={28} color="var(--accent-amber)" />
            <div>
              <div style={{ fontWeight: "800", color: "var(--accent-amber)", fontSize: "15px" }}>System Baseline: Normal & Clean</div>
              <div style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "3px" }}>
                No active brute-force attacks, SQL injections, or anomalies detected in <code>backend/logs/app_access.log</code>.
              </div>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            {recentAlerts.map((alert) => (
              <div
                key={alert.id}
                style={{
                  padding: "20px 24px",
                  background: "#ffffff",
                  border: `1px solid ${
                    alert.severity === "CRITICAL"
                      ? "rgba(225, 29, 72, 0.3)"
                      : alert.severity === "HIGH"
                      ? "rgba(234, 88, 12, 0.3)"
                      : "rgba(126, 34, 206, 0.25)"
                  }`,
                  borderRadius: "16px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px",
                  boxShadow: "0 2px 10px rgba(0, 0, 0, 0.03)",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
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
                    <strong style={{ color: "var(--text-primary)", fontSize: "15px" }}>{alert.alert_type.replace(/_/g, " ")}</strong>
                    <span className="hash-cell" style={{ fontSize: "12px" }}>IP: {alert.ip}</span>
                  </div>

                  <div style={{ fontSize: "12px", color: "var(--text-secondary)", display: "flex", gap: "16px", flexWrap: "wrap" }}>
                    <span>Target: <strong style={{ color: "var(--text-primary)" }}>{alert.target_user}</strong></span>
                    <span>Volume: <strong style={{ color: "var(--accent-rose)" }}>{alert.count} attempts</strong></span>
                  </div>
                </div>

                <div style={{ fontSize: "14px", color: "var(--text-secondary)", lineHeight: "1.5" }}>
                  {alert.message}
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px", color: "var(--text-muted)", paddingTop: "8px", borderTop: "1px solid var(--border-subtle)", flexWrap: "wrap", gap: "8px" }}>
                  <div>
                    <strong>First Seen:</strong> {alert.first_seen ? new Date(alert.first_seen).toLocaleTimeString() : "-"} &nbsp;|&nbsp; 
                    <strong>Last Seen:</strong> {alert.last_seen ? new Date(alert.last_seen).toLocaleTimeString() : "-"}
                  </div>
                  <div>
                    Window: <strong style={{ color: "var(--text-primary)" }}>{alert.time_window_seconds}s</strong>
                  </div>
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
            <span>Recently Encrypted Files</span>
          </div>
          <Link to="/files" className="btn-secondary" style={{ fontSize: "12px" }}>
            Open Vault →
          </Link>
        </div>

        {recentFiles.length === 0 ? (
          <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
            No files uploaded yet. Upload a confidential file to encrypt with AES-256.
          </div>
        ) : (
          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Encryption Standard</th>
                  <th>Plaintext Size</th>
                  <th>SHA-256 Digest</th>
                  <th style={{ textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentFiles.map((file) => (
                  <tr key={file.file_id}>
                    <td style={{ fontWeight: "700", color: "var(--text-primary)" }}>{file.filename}</td>
                    <td>
                      <span className="badge-tag badge-success">{file.encryption_algorithm || "AES-256-GCM"}</span>
                    </td>
                    <td>{(file.file_size / 1024).toFixed(1)} KB</td>
                    <td className="hash-cell" style={{ fontSize: "11px" }}>
                      {file.sha256_hash ? `${file.sha256_hash.slice(0, 16)}...` : "-"}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <a
                        href={`/api/files/download/${file.file_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="btn-secondary"
                        style={{ textDecoration: "none", fontSize: "12px", padding: "6px 14px" }}
                      >
                        <DownloadIcon size={14} /> Download
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