import { useState, useEffect } from "react";
import axios from "axios";

function ThreatCenter() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);
  const [selectedFilter, setSelectedFilter] = useState("ALL");
  const [mitigationCopied, setMitigationCopied] = useState(null);

  const fetchThreatData = async () => {
    try {
      setLoading(true);
      const alertsRes = await axios.get("http://localhost:5000/api/alerts?limit=100");
      setAlerts(alertsRes.data.alerts || []);
    } catch (e) {
      console.log("Analyzer offline:", e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreatData();
  }, []);

  const handleSimulate = async (attackType) => {
    try {
      setSimulating(attackType);
      setActionMessage(null);
      const res = await axios.post("http://localhost:5000/api/simulate", {
        attack_type: attackType,
      });
      setActionMessage({ type: "success", text: res.data.message });
      fetchThreatData();
    } catch (err) {
      setActionMessage({
        type: "error",
        text: "Simulation failed: " + (err.response?.data?.error || err.message),
      });
    } finally {
      setSimulating(null);
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm("Are you sure you want to clear access logs and reset the Threat Engine?")) return;

    try {
      setLoading(true);
      await axios.post("http://localhost:5000/api/clear-logs");
      setActionMessage({ type: "success", text: "Access logs cleared. Threat Engine reset to clean baseline." });
      fetchThreatData();
    } catch (err) {
      setActionMessage({ type: "error", text: "Reset failed: " + err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleCopyMitigation = (command, id) => {
    navigator.clipboard.writeText(command);
    setMitigationCopied(id);
    setTimeout(() => setMitigationCopied(null), 2500);
  };

  const filteredAlerts = alerts.filter((a) => {
    if (selectedFilter === "ALL") return true;
    return a.alert_type === selectedFilter || a.severity === selectedFilter;
  });

  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length;
  const highCount = alerts.filter((a) => a.severity === "HIGH").length;
  const bruteForceCount = alerts.filter((a) => a.alert_type === "BRUTE_FORCE_ATTACK").length;
  const sqliCount = alerts.filter((a) => a.alert_type === "SQL_INJECTION").length;
  const credStuffingCount = alerts.filter((a) => a.alert_type === "CREDENTIAL_STUFFING").length;
  const traversalCount = alerts.filter((a) => a.alert_type === "PATH_TRAVERSAL").length;

  return (
    <div className="threat-center-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">🛡️ SIEM Threat & Vulnerability Center</h1>
          <p className="page-subtitle">
            Live sliding-window detection for Brute Force, SQLi, Credential Stuffing, and Directory Traversal attacks
          </p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchThreatData} disabled={loading}>
            🔄 Refresh Feeds
          </button>
          <button className="btn-danger" onClick={handleClearLogs}>
            🧹 Reset Threat Baseline
          </button>
        </div>
      </div>

      {actionMessage && (
        <div
          style={{
            padding: "16px 20px",
            background: actionMessage.type === "success" ? "rgba(16, 185, 129, 0.15)" : "rgba(239, 68, 68, 0.15)",
            border: `1px solid ${actionMessage.type === "success" ? "rgba(16, 185, 129, 0.4)" : "rgba(239, 68, 68, 0.4)"}`,
            borderRadius: "12px",
            color: actionMessage.type === "success" ? "var(--accent-green)" : "#fca5a5",
            marginBottom: "24px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{actionMessage.type === "success" ? "⚡ " : "⚠️ "}{actionMessage.text}</span>
          <button
            style={{ background: "none", border: "none", color: "#fff", cursor: "pointer", fontSize: "16px" }}
            onClick={() => setActionMessage(null)}
          >
            ✕
          </button>
        </div>
      )}

      {/* Cyber Attack Simulation Console */}
      <div className="card-section" style={{ border: "1px solid rgba(59, 130, 246, 0.4)", background: "rgba(15, 23, 42, 0.9)" }}>
        <div className="section-header">
          <div className="section-title" style={{ color: "var(--accent-cyan)" }}>
            <span>⚡</span>
            <span>Interactive Cyber Attack Simulator & Payload Injector</span>
          </div>
          <span className="badge-tag badge-medium">Test Mode</span>
        </div>

        <p style={{ color: "var(--text-secondary)", fontSize: "14px", marginBottom: "20px" }}>
          Click any attack vector below to inject realistic forensic log streams into the SIEM pipeline and watch the detection engine respond in real time:
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px" }}>
          <button
            className="btn-primary"
            style={{ background: "linear-gradient(135deg, #dc2626, #b91c1c)" }}
            onClick={() => handleSimulate("brute_force")}
            disabled={simulating !== null}
          >
            {simulating === "brute_force" ? "Injecting..." : "🔴 Simulate Brute Force"}
          </button>

          <button
            className="btn-primary"
            style={{ background: "linear-gradient(135deg, #9333ea, #7e22ce)" }}
            onClick={() => handleSimulate("sqli")}
            disabled={simulating !== null}
          >
            {simulating === "sqli" ? "Injecting..." : "💉 Simulate SQL Injection"}
          </button>

          <button
            className="btn-primary"
            style={{ background: "linear-gradient(135deg, #d97706, #b45309)" }}
            onClick={() => handleSimulate("credential_stuffing")}
            disabled={simulating !== null}
          >
            {simulating === "credential_stuffing" ? "Injecting..." : "👥 Simulate Credential Stuffing"}
          </button>

          <button
            className="btn-primary"
            style={{ background: "linear-gradient(135deg, #2563eb, #1d4ed8)" }}
            onClick={() => handleSimulate("path_traversal")}
            disabled={simulating !== null}
          >
            {simulating === "path_traversal" ? "Injecting..." : "📂 Simulate Path Traversal"}
          </button>

          <button
            className="btn-primary"
            style={{ background: "var(--gradient-cyber)", gridColumn: "1 / -1" }}
            onClick={() => handleSimulate("all")}
            disabled={simulating !== null}
          >
            {simulating === "all" ? "Injecting Full Attack Stream..." : "⚡ Simulate Full Multi-Vector Attack (All Vectors Combined)"}
          </button>
        </div>
      </div>

      {/* Threat Summary Stats Grid */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(239, 68, 68, 0.2)", borderColor: "rgba(239, 68, 68, 0.4)" }}>
            🚨
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-red)" }}>{criticalCount}</div>
            <div className="stat-label">Critical Severity Threats</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(245, 158, 11, 0.2)", borderColor: "rgba(245, 158, 11, 0.4)" }}>
            ⚠️
          </div>
          <div>
            <div className="stat-value" style={{ color: "var(--accent-yellow)" }}>{highCount}</div>
            <div className="stat-label">High Severity Threats</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(59, 130, 246, 0.2)", borderColor: "rgba(59, 130, 246, 0.4)" }}>
            🔨
          </div>
          <div>
            <div className="stat-value">{bruteForceCount}</div>
            <div className="stat-label">Brute Force Attacks</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: "rgba(139, 92, 246, 0.2)", borderColor: "rgba(139, 92, 246, 0.4)" }}>
            💉
          </div>
          <div>
            <div className="stat-value">{sqliCount + traversalCount}</div>
            <div className="stat-label">Web Probing & Injections</div>
          </div>
        </div>
      </div>

      {/* Threat Category Filter Chips */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "20px" }}>
        {[
          { label: `All Threats (${alerts.length})`, value: "ALL" },
          { label: `Brute Force (${bruteForceCount})`, value: "BRUTE_FORCE_ATTACK" },
          { label: `SQL Injection (${sqliCount})`, value: "SQL_INJECTION" },
          { label: `Credential Stuffing (${credStuffingCount})`, value: "CREDENTIAL_STUFFING" },
          { label: `Path Traversal (${traversalCount})`, value: "PATH_TRAVERSAL" },
          { label: `Critical Only (${criticalCount})`, value: "CRITICAL" },
        ].map((chip) => (
          <button
            key={chip.value}
            className={selectedFilter === chip.value ? "btn-primary" : "btn-secondary"}
            style={{ fontSize: "13px", padding: "8px 16px" }}
            onClick={() => setSelectedFilter(chip.value)}
          >
            {chip.label}
          </button>
        ))}
      </div>

      {/* Identified Vulnerabilities & Incident Cards */}
      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>🎯</span>
            <span>Identified Incidents & Automated Mitigation Engine ({filteredAlerts.length})</span>
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            Monitored Log File: <code>backend/logs/app_access.log</code>
          </div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 24px" }}>
            <div style={{ fontSize: "44px", marginBottom: "12px" }}>🛡️</div>
            <h3 style={{ color: "#fff", marginBottom: "6px" }}>No Threats Matching Active Filter</h3>
            <p style={{ color: "var(--text-secondary)", marginBottom: "16px" }}>
              Click on the attack simulator buttons above to inject test payloads and evaluate detection.
            </p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
            {filteredAlerts.map((alert) => {
              const firewallCmd = `iptables -A INPUT -s ${alert.ip} -j DROP # Block ${alert.alert_type}`;
              return (
                <div
                  key={alert.id}
                  style={{
                    background: "rgba(17, 24, 39, 0.9)",
                    border: `1px solid ${
                      alert.severity === "CRITICAL"
                        ? "rgba(239, 68, 68, 0.5)"
                        : alert.severity === "HIGH"
                        ? "rgba(245, 158, 11, 0.4)"
                        : "rgba(59, 130, 246, 0.4)"
                    }`,
                    borderRadius: "16px",
                    padding: "24px",
                    boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.4)",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "12px" }}>
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
                      <h2 style={{ fontSize: "17px", fontWeight: "700", color: "#fff" }}>
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

                  {/* Forensic Metadata Grid */}
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                      gap: "12px",
                      padding: "14px 18px",
                      background: "rgba(15, 23, 42, 0.8)",
                      borderRadius: "10px",
                      marginBottom: "16px",
                      fontSize: "13px",
                    }}
                  >
                    <div>
                      <span style={{ color: "var(--text-secondary)" }}>Targeted Account: </span>
                      <strong style={{ color: "#fff" }}>{alert.target_user}</strong>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-secondary)" }}>Attack Volume: </span>
                      <strong style={{ color: "var(--accent-red)" }}>{alert.count} attempts</strong>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-secondary)" }}>Time Window: </span>
                      <strong style={{ color: "#fff" }}>{alert.time_window_seconds} seconds</strong>
                    </div>
                    <div>
                      <span style={{ color: "var(--text-secondary)" }}>Timestamp: </span>
                      <strong style={{ color: "#fff" }}>{new Date(alert.last_seen).toLocaleTimeString()}</strong>
                    </div>
                  </div>

                  {/* Automated Firewall Mitigation Command */}
                  <div
                    style={{
                      background: "rgba(6, 182, 212, 0.08)",
                      border: "1px solid rgba(6, 182, 212, 0.25)",
                      borderRadius: "10px",
                      padding: "14px 18px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "12px", fontWeight: "600", color: "var(--accent-cyan)", marginBottom: "4px" }}>
                        🛡️ Recommended Automated Remediation:
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
                      {mitigationCopied === alert.id ? "✓ Copied IP Drop Rule" : "📋 Copy Firewall Rule"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatCenter;
