import { useState, useEffect } from "react";
import axios from "axios";

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      // Try proxied /api/stats, fallback to direct port 5001 if proxy is inactive
      let res;
      try {
        res = await axios.get("/api/stats");
      } catch {
        res = await axios.get("http://localhost:5001/api/stats");
      }
      setStats(res.data);
    } catch (err) {
      console.warn("Could not reach Analyzer API:", err.message);
      setError("Log Analyzer API offline. Start backend analyzer service on port 5001.");
    } finally {
      setLoading(false);
    }
  };

  const triggerAnalyze = async () => {
    try {
      setScanning(true);
      try {
        await axios.post("/api/analyze", {});
      } catch {
        await axios.post("http://localhost:5001/api/analyze", {});
      }
      await fetchStats();
    } catch (err) {
      console.error("Scan trigger failed:", err.message);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const summary = stats?.summary || {
    security_score: 100,
    system_status: "SECURE",
    total_requests: 0,
    total_alerts: 0,
    total_failed_logins: 0,
    critical_alerts: 0,
    high_alerts: 0
  };

  return (
    <div className="dashboard">
      <div className="header-row">
        <div>
          <h1>Security Command Center</h1>
          <p className="dashboard-subtitle">
            Real-time Threat Monitoring & Cybersecurity Intelligence for SecureShare
          </p>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button className="btn-secondary" onClick={fetchStats} disabled={loading}>
            🔄 Refresh
          </button>
          <button className="btn-primary" onClick={triggerAnalyze} disabled={scanning}>
            {scanning ? "🔍 Scanning Logs..." : "🛡️ Run Deep Log Analysis"}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ background: "rgba(239, 68, 68, 0.15)", border: "1px solid #ef4444", padding: "12px 16px", borderRadius: "8px", marginBottom: "20px", color: "#fca5a5" }}>
          ⚠️ {error}
        </div>
      )}

      {/* System Status Banner */}
      <div className={`status-banner ${summary.system_status}`}>
        <div>
          <div style={{ fontSize: "12px", textTransform: "uppercase", letterSpacing: "1px", color: "#cbd5e1" }}>
            Current Threat Posture
          </div>
          <div style={{ fontSize: "22px", fontWeight: "800", marginTop: "4px" }}>
            {summary.system_status.replace("_", " ")}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: "12px", color: "#cbd5e1" }}>Security Score</div>
            <div style={{ fontSize: "26px", fontWeight: "800", color: summary.security_score >= 80 ? "#34d399" : summary.security_score >= 50 ? "#fbbf24" : "#f87171" }}>
              {summary.security_score}/100
            </div>
          </div>
          <span className={`status-badge ${summary.critical_alerts > 0 ? "badge-critical" : summary.high_alerts > 0 ? "badge-high" : "badge-secure"}`}>
            {summary.system_status}
          </span>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="stats-container">
        <div className="stat-card">
          <div className="stat-icon">🛡️</div>
          <div>
            <h3>Security Score</h3>
            <p>{summary.security_score}%</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">🚨</div>
          <div>
            <h3>Active Alerts</h3>
            <p style={{ color: summary.total_alerts > 0 ? "#ef4444" : "#f8fafc" }}>
              {summary.total_alerts}
            </p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">🔒</div>
          <div>
            <h3>Failed Logins</h3>
            <p style={{ color: summary.total_failed_logins > 0 ? "#f97316" : "#f8fafc" }}>
              {summary.total_failed_logins}
            </p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div>
            <h3>Total Requests</h3>
            <p>{summary.total_requests}</p>
          </div>
        </div>
      </div>

      {/* Threat Breakdown and Offending IPs */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "20px" }}>
        
        {/* Threat Distribution */}
        <div className="card-panel">
          <h2>🎯 Threat Category Breakdown</h2>
          {stats?.threat_breakdown && Object.keys(stats.threat_breakdown).length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginTop: "15px" }}>
              {Object.entries(stats.threat_breakdown).map(([type, count]) => (
                <div key={type} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f172a", padding: "10px 14px", borderRadius: "8px", border: "1px solid #334155" }}>
                  <span style={{ fontWeight: "600", fontSize: "14px" }}>{type.replace(/_/g, " ")}</span>
                  <span className="badge-critical" style={{ padding: "3px 10px", borderRadius: "12px", fontSize: "12px", fontWeight: "700" }}>
                    {count} incident{count > 1 ? "s" : ""}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: "#94a3b8", marginTop: "15px" }}>✅ No malicious threat signatures identified in active logs.</p>
          )}
        </div>

        {/* Top Offending Attacker IPs */}
        <div className="card-panel">
          <h2>🌐 Top Flagged Offending IPs</h2>
          {stats?.top_offending_ips && stats.top_offending_ips.length > 0 ? (
            <div className="table-responsive" style={{ marginTop: "15px" }}>
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Failed Logins</th>
                    <th>Alerts</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.top_offending_ips.slice(0, 5).map((item) => (
                    <tr key={item.ip}>
                      <td><span className="code-badge">{item.ip}</span></td>
                      <td style={{ color: item.failed_logins > 0 ? "#f87171" : "#e2e8f0" }}>{item.failed_logins}</td>
                      <td>
                        <span className={`status-badge ${item.alert_count > 0 ? "badge-critical" : "badge-secure"}`} style={{ padding: "2px 8px", fontSize: "11px" }}>
                          {item.alert_count}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p style={{ color: "#94a3b8", marginTop: "15px" }}>✅ No suspicious IP addresses recorded.</p>
          )}
        </div>

      </div>

      {/* Recent Alerts Feed */}
      <div className="recent-section">
        <h2>⚡ High-Priority Security Incidents</h2>
        {stats?.recent_alerts && stats.recent_alerts.length > 0 ? (
          <div className="alerts-list">
            {stats.recent_alerts.map((alert) => (
              <div key={alert.id} className={`alert-item ${alert.severity}`}>
                <div className="alert-header">
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span className={`status-badge badge-${alert.severity.toLowerCase()}`}>
                      {alert.severity}
                    </span>
                    <span className="alert-title">{alert.alert_type.replace(/_/g, " ")}</span>
                  </div>
                  <span className="alert-time">
                    {new Date(alert.last_seen).toLocaleTimeString()}
                  </span>
                </div>
                <div className="alert-msg">{alert.message}</div>
                {alert.mitigation_advice && (
                  <div className="alert-mitigation">
                    💡 <strong>Mitigation:</strong> {alert.mitigation_advice}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="card-panel" style={{ textAlign: "center", color: "#94a3b8" }}>
            <p>🛡️ All systems operating normally. Zero active security alerts.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;