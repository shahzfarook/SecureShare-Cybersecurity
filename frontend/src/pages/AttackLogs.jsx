import { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { SearchIcon, RefreshIcon, LogIcon, DownloadIcon, AlertIcon, ShieldIcon, CopyIcon, CheckIcon, TerminalIcon } from "../components/Icons";

function AttackLogs() {
  const [activeTab, setActiveTab] = useState("incidents"); // 'incidents' | 'raw_logs'
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("ALL");
  const [mitigationCopied, setMitigationCopied] = useState(null);

  const fetchLogData = async () => {
    try {
      setLoading(true);

      // 1. Fetch Alerts (Port 5001)
      let alertsRes;
      try {
        alertsRes = await axios.get("/api/alerts?limit=100");
      } catch {
        alertsRes = await axios.get("http://localhost:5001/api/alerts?limit=100");
      }
      setAlerts(alertsRes.data.alerts || []);

      // 2. Fetch Raw Logs (Port 5001)
      let queryStr = `limit=100${search ? `&search=${encodeURIComponent(search)}` : ""}${statusFilter ? `&status=${encodeURIComponent(statusFilter)}` : ""}`;
      let logsRes;
      try {
        logsRes = await axios.get(`/api/logs?${queryStr}`);
      } catch {
        logsRes = await axios.get(`http://localhost:5001/api/logs?${queryStr}`);
      }
      setLogs(logsRes.data.logs || []);

      // 3. Fetch Stats (Port 5001)
      let statsRes;
      try {
        statsRes = await axios.get("/api/stats");
      } catch {
        statsRes = await axios.get("http://localhost:5001/api/stats");
      }
      setStats(statsRes.data || null);
    } catch (e) {
      console.log("Log data fetch error:", e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogData();
    const interval = setInterval(fetchLogData, 8000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const handleCopyMitigation = (command, id) => {
    navigator.clipboard.writeText(command);
    setMitigationCopied(id);
    setTimeout(() => setMitigationCopied(null), 2500);
  };

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ alerts, logs }, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `secureshare_logs_export_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredAlerts = alerts.filter((a) => {
    if (selectedSeverity === "ALL") return true;
    return a.severity === selectedSeverity || a.alert_type === selectedSeverity;
  });

  const filteredLogs = logs.filter((log) => {
    if (!methodFilter) return true;
    return log.method === methodFilter;
  });

  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const highCount = alerts.filter((a) => a.severity === "HIGH").length;
  const totalAnalyzed = stats?.summary?.total_requests || logs.length;

  return (
    <div className="logs-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack & Audit Logs</h1>
          <p className="page-subtitle">
            Forensic analysis of detected threat incidents and raw access events parsed from <code>backend/logs/app_access.log</code>
          </p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <Link to="/simulator" className="btn-primary" style={{ fontSize: "13px" }}>
            <TerminalIcon size={16} /> Open Attack Simulator
          </Link>
          <button className="btn-secondary" onClick={handleExportJSON} disabled={logs.length === 0 && alerts.length === 0}>
            <DownloadIcon size={16} /> Export JSON
          </button>
          <button className="btn-secondary" onClick={fetchLogData} disabled={loading}>
            <RefreshIcon size={16} /> Refresh
          </button>
        </div>
      </div>

      {/* Metric Summary Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-primary-subtle)", borderColor: "rgba(126, 34, 206, 0.2)" }}>
            <LogIcon size={22} color="var(--accent-primary)" />
          </div>
          <div>
            <div className="stat-value">{totalAnalyzed}</div>
            <div className="stat-label">Total Log Events</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-rose-subtle)", borderColor: "var(--accent-rose-border)" }}>
            <AlertIcon size={22} color="var(--accent-rose)" />
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-rose)" }}>{alerts.length}</div>
            <div className="stat-label">Flagged Security Incidents</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-orange-subtle)", borderColor: "var(--accent-orange-border)" }}>
            <AlertIcon size={22} color="var(--accent-orange)" />
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-orange)" }}>{criticalCount + highCount}</div>
            <div className="stat-label">Critical & High Priority</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "var(--accent-amber-subtle)", borderColor: "var(--accent-amber-border)" }}>
            <ShieldIcon size={22} color="var(--accent-amber)" />
          </div>
          <div>
            <div className="stat-value">{stats?.summary?.unique_ips || 0}</div>
            <div className="stat-label">Distinct IP Sources</div>
          </div>
        </div>
      </div>

      {/* Dual Tab Switcher */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "24px" }}>
        <button
          className={activeTab === "incidents" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveTab("incidents")}
          style={{ padding: "10px 20px" }}
        >
          <AlertIcon size={16} />
          <span>Detected Threat Incidents ({alerts.length})</span>
        </button>

        <button
          className={activeTab === "raw_logs" ? "btn-primary" : "btn-secondary"}
          onClick={() => setActiveTab("raw_logs")}
          style={{ padding: "10px 20px" }}
        >
          <LogIcon size={16} />
          <span>Raw Access Audit Stream ({logs.length})</span>
        </button>
      </div>

      {/* TAB 1: Detected Threat Incidents */}
      {activeTab === "incidents" ? (
        <div className="card-section">
          <div className="section-header">
            <div className="section-title">
              <span>Security Threat Incidents & Automated Remediation Rules</span>
            </div>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              {["ALL", "CRITICAL", "HIGH", "BRUTE_FORCE_ATTACK", "SQL_INJECTION", "CREDENTIAL_STUFFING"].map((sev) => (
                <button
                  key={sev}
                  className={selectedSeverity === sev ? "btn-primary" : "btn-secondary"}
                  style={{ fontSize: "11px", padding: "5px 12px" }}
                  onClick={() => setSelectedSeverity(sev)}
                >
                  {sev.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          </div>

          {filteredAlerts.length === 0 ? (
            <div style={{ textAlign: "center", padding: "48px 24px" }}>
              <div style={{ display: "inline-flex", padding: "16px", borderRadius: "50%", background: "var(--accent-amber-subtle)", marginBottom: "16px" }}>
                <ShieldIcon size={36} color="var(--accent-amber)" />
              </div>
              <h3 style={{ color: "var(--text-primary)", marginBottom: "6px", fontWeight: "800" }}>No Active Threat Incidents</h3>
              <p style={{ color: "var(--text-secondary)", marginBottom: "16px" }}>
                All access logs in <code>backend/logs/app_access.log</code> match legitimate operational traffic.
              </p>
              <Link to="/simulator" className="btn-secondary" style={{ fontSize: "13px" }}>
                Launch Simulator Scenario →
              </Link>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {filteredAlerts.map((alert) => {
                const firewallCmd = `iptables -A INPUT -s ${alert.ip} -j DROP # Block ${alert.alert_type}`;
                return (
                  <div
                    key={alert.id}
                    style={{
                      background: "#ffffff",
                      border: `1px solid ${
                        alert.severity === "CRITICAL"
                          ? "rgba(225, 29, 72, 0.35)"
                          : alert.severity === "HIGH"
                          ? "rgba(234, 88, 12, 0.35)"
                          : "rgba(126, 34, 206, 0.25)"
                      }`,
                      borderRadius: "16px",
                      padding: "24px",
                      boxShadow: "var(--shadow-sm)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px", flexWrap: "wrap", gap: "10px" }}>
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
                        <h2 style={{ fontSize: "16px", fontWeight: "800", color: "var(--text-primary)" }}>
                          {alert.alert_type.replace(/_/g, " ")}
                        </h2>
                      </div>

                      <div className="hash-cell" style={{ fontSize: "12px" }}>
                        Attacker IP: <strong>{alert.ip}</strong>
                      </div>
                    </div>

                    <p style={{ fontSize: "14px", color: "var(--text-primary)", marginBottom: "16px", lineHeight: "1.5" }}>
                      {alert.message}
                    </p>

                    {/* Forensic Metadata */}
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                        gap: "12px",
                        padding: "16px 20px",
                        background: "#f8fafc",
                        borderRadius: "12px",
                        marginBottom: "16px",
                        fontSize: "13px",
                        border: "1px solid var(--border-color)",
                      }}
                    >
                      <div>
                        <span style={{ color: "var(--text-secondary)" }}>Targeted User: </span>
                        <strong style={{ color: "var(--text-primary)" }}>{alert.target_user}</strong>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-secondary)" }}>Attack Volume: </span>
                        <strong style={{ color: "var(--accent-rose)" }}>{alert.count} attempts</strong>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-secondary)" }}>Time Window: </span>
                        <strong style={{ color: "var(--text-primary)" }}>{alert.time_window_seconds}s</strong>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-secondary)" }}>First Seen: </span>
                        <strong style={{ color: "var(--text-primary)" }}>{alert.first_seen ? new Date(alert.first_seen).toLocaleTimeString() : "-"}</strong>
                      </div>
                      <div>
                        <span style={{ color: "var(--text-secondary)" }}>Last Seen: </span>
                        <strong style={{ color: "var(--text-primary)" }}>{alert.last_seen ? new Date(alert.last_seen).toLocaleTimeString() : "-"}</strong>
                      </div>
                    </div>

                    {/* Automated Firewall Command */}
                    <div
                      style={{
                        background: "var(--accent-primary-subtle)",
                        border: "1px solid rgba(126, 34, 206, 0.2)",
                        borderRadius: "12px",
                        padding: "16px 20px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        flexWrap: "wrap",
                        gap: "12px",
                      }}
                    >
                      <div>
                        <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--accent-primary)", marginBottom: "4px" }}>
                          Automated Firewall Remediation Rule:
                        </div>
                        <div style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                          {alert.mitigation_advice}
                        </div>
                      </div>

                      <button
                        className="btn-secondary"
                        style={{ fontSize: "12px", whiteSpace: "nowrap" }}
                        onClick={() => handleCopyMitigation(firewallCmd, alert.id)}
                      >
                        {mitigationCopied === alert.id ? (
                          <>
                            <CheckIcon size={14} /> Copied Drop Rule
                          </>
                        ) : (
                          <>
                            <CopyIcon size={14} /> Copy Firewall Rule
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : (
        /* TAB 2: Raw Access Audit Logs */
        <div className="card-section">
          <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", alignItems: "center", marginBottom: "22px" }}>
            <div style={{ position: "relative", flex: 1, minWidth: "260px" }}>
              <input
                type="text"
                className="cyber-input"
                placeholder="Search by IP, username, endpoint, or message..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && fetchLogData()}
              />
            </div>

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

            <select
              className="cyber-input"
              style={{ width: "140px" }}
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
            >
              <option value="">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>

            <button className="btn-secondary" onClick={fetchLogData}>
              <SearchIcon size={16} /> Search
            </button>
          </div>

          <div className="section-header">
            <div className="section-title">
              <span>Access Log Entries ({filteredLogs.length})</span>
            </div>
            <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
              Source: <code>backend/logs/app_access.log</code>
            </div>
          </div>

          {filteredLogs.length === 0 ? (
            <div style={{ textAlign: "center", padding: "48px", color: "var(--text-secondary)" }}>
              No access log events matched your search criteria.
            </div>
          ) : (
            <div className="cyber-table-wrapper">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Method & Endpoint</th>
                    <th>User Identity</th>
                    <th>Status</th>
                    <th>Audit Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log, idx) => (
                    <tr key={idx}>
                      <td style={{ fontSize: "12px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <span className="hash-cell" style={{ fontSize: "12px" }}>{log.ip}</span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontWeight: "800",
                            color: log.method === "POST" ? "var(--accent-primary)" : "var(--accent-orange)",
                            marginRight: "8px",
                            fontSize: "12px",
                          }}
                        >
                          {log.method}
                        </span>
                        <span style={{ color: "var(--text-primary)", fontSize: "13px", fontWeight: "600" }}>
                          {log.endpoint}
                        </span>
                      </td>
                      <td style={{ fontWeight: "700", color: log.user !== "anonymous" ? "var(--accent-amber)" : "var(--text-muted)" }}>
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
                      <td
                        style={{
                          fontSize: "13px",
                          color: "var(--text-secondary)",
                          maxWidth: "360px",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                        title={log.message}
                      >
                        {log.message}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AttackLogs;
