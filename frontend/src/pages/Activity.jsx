import { useState, useEffect, useCallback } from "react";
import axios from "axios";

function Activity() {
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [activeTab, setActiveTab] = useState("logs"); // "logs" | "alerts"
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      // Fetch logs
      try {
        const logRes = await axios.get(`/api/logs?limit=100${search ? `&search=${encodeURIComponent(search)}` : ""}${statusFilter ? `&status=${statusFilter}` : ""}`);
        setLogs(logRes.data.logs || []);
      } catch {
        const logRes = await axios.get(`http://localhost:5001/api/logs?limit=100${search ? `&search=${encodeURIComponent(search)}` : ""}${statusFilter ? `&status=${statusFilter}` : ""}`);
        setLogs(logRes.data.logs || []);
      }

      // Fetch alerts
      try {
        const alertRes = await axios.get(`/api/alerts?limit=50${severityFilter ? `&severity=${severityFilter}` : ""}`);
        setAlerts(alertRes.data.alerts || []);
      } catch {
        const alertRes = await axios.get(`http://localhost:5001/api/alerts?limit=50${severityFilter ? `&severity=${severityFilter}` : ""}`);
        setAlerts(alertRes.data.alerts || []);
      }
    } catch (err) {
      console.warn("Failed to fetch activity:", err.message);
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, severityFilter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const getStatusClass = (code) => {
    if (code >= 200 && code < 300) return "status-code-200";
    if (code === 400) return "status-code-400";
    if (code === 401) return "status-code-401";
    if (code === 403) return "status-code-403";
    return "status-code-500";
  };

  return (
    <div className="activity-page">
      <div className="header-row">
        <div>
          <h1>Activity & Audit Logs</h1>
          <p className="page-subtitle">
            Live stream of access attempts, authentication events, and detected threat alerts.
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            className={activeTab === "logs" ? "btn-primary" : "btn-secondary"}
            onClick={() => setActiveTab("logs")}
          >
            📋 Raw Access Logs ({logs.length})
          </button>
          <button
            className={activeTab === "alerts" ? "btn-primary" : "btn-secondary"}
            onClick={() => setActiveTab("alerts")}
          >
            🚨 Security Alerts ({alerts.length})
          </button>
          <button className="btn-secondary" onClick={fetchData} disabled={loading}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {activeTab === "logs" ? (
        <div className="card-panel">
          <div className="filters-bar">
            <input
              type="text"
              placeholder="Search by IP, username, endpoint, or message..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="select-filter"
            >
              <option value="">All Status Codes</option>
              <option value="200">200 OK</option>
              <option value="400">400 Bad Request</option>
              <option value="401">401 Unauthorized / Failed Login</option>
              <option value="403">403 Forbidden</option>
              <option value="404">404 Not Found</option>
              <option value="500">500 Server Error</option>
            </select>
          </div>

          <div className="table-responsive">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>Method</th>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>User</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.length > 0 ? (
                  logs.map((log, index) => (
                    <tr key={index}>
                      <td style={{ fontSize: "12px", color: "#94a3b8", whiteSpace: "nowrap" }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td><span className="code-badge">{log.ip}</span></td>
                      <td><strong>{log.method}</strong></td>
                      <td style={{ color: "#38bdf8" }}>{log.endpoint}</td>
                      <td>
                        <span className={`status-code-pill ${getStatusClass(log.status_code)}`}>
                          {log.status_code}
                        </span>
                      </td>
                      <td>{log.user}</td>
                      <td style={{ maxWidth: "300px", color: "#cbd5e1" }}>{log.message}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" style={{ textAlign: "center", color: "#94a3b8", padding: "30px" }}>
                      {loading ? "Loading access logs..." : "No access logs match the selected filters."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card-panel">
          <div className="filters-bar">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="select-filter"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="alerts-list">
            {alerts.length > 0 ? (
              alerts.map((alert) => (
                <div key={alert.id} className={`alert-item ${alert.severity}`}>
                  <div className="alert-header">
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <span className={`status-badge badge-${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </span>
                      <span className="alert-title">{alert.alert_type.replace(/_/g, " ")}</span>
                      <span className="code-badge">{alert.ip}</span>
                    </div>
                    <span className="alert-time">
                      {new Date(alert.last_seen).toLocaleString()}
                    </span>
                  </div>
                  <div className="alert-msg">{alert.message}</div>
                  <div style={{ fontSize: "13px", color: "#94a3b8" }}>
                    Target User: <strong style={{ color: "#f1f5f9" }}>{alert.target_user}</strong> | Incident Count: <strong style={{ color: "#f1f5f9" }}>{alert.count}</strong> | Window: {alert.time_window_seconds}s
                  </div>
                  {alert.mitigation_advice && (
                    <div className="alert-mitigation">
                      💡 <strong>Recommended Mitigation:</strong> {alert.mitigation_advice}
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div style={{ textAlign: "center", color: "#94a3b8", padding: "30px" }}>
                {loading ? "Loading alerts..." : "No security alerts found matching the filter."}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Activity;