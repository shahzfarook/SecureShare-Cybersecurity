import { useState, useEffect } from "react";
import axios from "axios";

function Activity() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [activeTab, setActiveTab] = useState("alerts"); // 'alerts' | 'logs'
  const [scanMessage, setScanMessage] = useState(null);

  const fetchActivityData = async () => {
    // 1. Fetch Alerts
    try {
      const alertsRes = await axios.get("http://localhost:5000/api/alerts?limit=50");
      setAlerts(alertsRes.data.alerts || []);
    } catch (e) {
      console.log("Alerts offline:", e.message);
    }

    // 2. Fetch Logs
    try {
      let url = "http://localhost:5000/api/logs?limit=50";
      if (search) url += `&search=${encodeURIComponent(search)}`;
      if (statusFilter) url += `&status=${encodeURIComponent(statusFilter)}`;
      const logsRes = await axios.get(url);
      setLogs(logsRes.data.logs || []);
    } catch (e) {
      console.log("Logs offline:", e.message);
    }
  };

  useEffect(() => {
    fetchActivityData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const handleScan = async () => {
    try {
      setScanning(true);
      const res = await axios.post("http://localhost:5000/api/analyze");
      setScanMessage(res.data.message || "Security scan complete!");
      fetchActivityData();
    } catch (err) {
      setScanMessage("Scan failed: " + (err.response?.data?.error || err.message));
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="activity-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Center & Audit Activity</h1>
          <p className="page-subtitle">Sliding-window threat detection, audit access logs, and attack mitigation</p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchActivityData}>
            🔄 Refresh
          </button>
          <button className="btn-primary" onClick={handleScan} disabled={scanning}>
            {scanning ? "Scanning Logs..." : "⚡ Trigger Threat Scan"}
          </button>
        </div>
      </div>

      {scanMessage && (
        <div style={{ padding: "14px 20px", background: "rgba(59, 130, 246, 0.15)", border: "1px solid rgba(59, 130, 246, 0.3)", borderRadius: "12px", color: "var(--accent-cyan)", marginBottom: "24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span>ℹ️ {scanMessage}</span>
          <button style={{ background: "none", border: "none", color: "#fff", cursor: "pointer" }} onClick={() => setScanMessage(null)}>✕</button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
        <button
          className={activeTab === "alerts" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveTab("alerts")}
        >
          🛡️ Threat Alerts ({alerts.length})
        </button>

        <button
          className={activeTab === "logs" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveTab("logs")}
        >
          📜 Access Audit Logs ({logs.length})
        </button>
      </div>

      {activeTab === "alerts" ? (
        <div className="card-section">
          <div className="section-header">
            <div className="section-title">
              <span>🚨</span>
              <span>Identified Cybersecurity Threats</span>
            </div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
              Sliding Window: 60s Brute Force | 120s Credential Stuffing
            </div>
          </div>

          {alerts.length === 0 ? (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-secondary)" }}>
              No threat alerts found. The system is clean.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  style={{
                    padding: "20px",
                    background: "rgba(15, 23, 42, 0.7)",
                    border: `1px solid ${alert.severity === "CRITICAL" ? "rgba(239, 68, 68, 0.5)" : "rgba(245, 158, 11, 0.4)"}`,
                    borderRadius: "14px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "10px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
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
                      <h3 style={{ color: "#fff", fontSize: "16px" }}>{alert.alert_type}</h3>
                      <span className="hash-cell">IP: {alert.ip}</span>
                    </div>

                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace" }}>
                      {alert.id}
                    </div>
                  </div>

                  <div style={{ fontSize: "14px", color: "var(--text-primary)", marginBottom: "12px" }}>
                    {alert.message}
                  </div>

                  <div style={{ background: "rgba(17, 24, 39, 0.9)", padding: "12px 16px", borderRadius: "10px", border: "1px solid var(--border-color)", fontSize: "13px" }}>
                    <strong style={{ color: "var(--accent-cyan)" }}>🛡️ Mitigation Advice: </strong>
                    <span style={{ color: "var(--text-secondary)" }}>{alert.mitigation_advice}</span>
                  </div>

                  <div style={{ marginTop: "12px", display: "flex", gap: "20px", fontSize: "12px", color: "var(--text-muted)" }}>
                    <span>Target: <strong style={{ color: "#fff" }}>{alert.target_user}</strong></span>
                    <span>Event Count: <strong style={{ color: "#fff" }}>{alert.count}</strong></span>
                    <span>Time Window: <strong style={{ color: "#fff" }}>{alert.time_window_seconds}s</strong></span>
                    <span>First Seen: {new Date(alert.first_seen).toLocaleTimeString()}</span>
                    <span>Last Seen: {new Date(alert.last_seen).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="card-section">
          {/* Log search & filters */}
          <div style={{ display: "flex", gap: "12px", marginBottom: "20px" }}>
            <input
              type="text"
              className="cyber-input"
              placeholder="Search by IP, username, endpoint..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && fetchActivityData()}
              style={{ flex: 1 }}
            />

            <select
              className="cyber-input"
              style={{ width: "160px" }}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="">All Statuses</option>
              <option value="200">200 (Success)</option>
              <option value="401">401 (Unauthorized)</option>
              <option value="403">403 (Forbidden)</option>
              <option value="404">404 (Not Found)</option>
              <option value="500">500 (Server Error)</option>
            </select>

            <button className="btn-secondary" onClick={fetchActivityData}>
              Search
            </button>
          </div>

          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>Method & Endpoint</th>
                  <th>User</th>
                  <th>Status</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, idx) => (
                  <tr key={idx}>
                    <td style={{ fontSize: "12px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="hash-cell" style={{ fontSize: "12px" }}>{log.ip}</span>
                    </td>
                    <td>
                      <span style={{ fontWeight: "700", color: log.method === "POST" ? "var(--accent-cyan)" : "var(--accent-purple)", marginRight: "6px" }}>
                        {log.method}
                      </span>
                      <span style={{ color: "#fff", fontSize: "13px" }}>{log.endpoint}</span>
                    </td>
                    <td style={{ fontWeight: "600", color: log.user !== "anonymous" ? "var(--accent-green)" : "var(--text-muted)" }}>
                      {log.user}
                    </td>
                    <td>
                      <span
                        className={`badge-tag ${
                          log.status_code === 200
                            ? "badge-success"
                            : log.status_code === 401
                            ? "badge-critical"
                            : log.status_code === 403
                            ? "badge-high"
                            : "badge-medium"
                        }`}
                      >
                        {log.status_code}
                      </span>
                    </td>
                    <td style={{ fontSize: "13px", color: "var(--text-secondary)", maxWidth: "320px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={log.message}>
                      {log.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default Activity;