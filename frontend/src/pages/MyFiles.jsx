import { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

function MyFiles() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationResult, setVerificationResult] = useState({});

  const fetchFiles = async () => {
    try {
      setLoading(true);
      const res = await axios.get("http://localhost:8001/api/files/list");
      setFiles(res.data);
      setError(null);
    } catch {
      setError("Could not connect to File Sharing API (port 8001). Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleVerifyIntegrity = async (fileId) => {
    try {
      setVerifyingId(fileId);
      const res = await axios.get(`http://localhost:8001/api/files/verify/${fileId}`);
      setVerificationResult((prev) => ({ ...prev, [fileId]: res.data }));
    } catch (err) {
      alert("Verification failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm("Are you sure you want to securely delete this encrypted file?")) return;

    try {
      await axios.delete(`http://localhost:8001/api/files/${fileId}`);
      setFiles(files.filter((f) => f.file_id !== fileId));
    } catch (err) {
      alert("Delete failed: " + (err.response?.data?.detail || err.message));
    }
  };

  const handleDownload = (fileId) => {
    window.open(`http://localhost:8001/api/files/download/${fileId}`, "_blank");
  };

  const filteredFiles = files.filter(
    (f) =>
      f.filename?.toLowerCase().includes(search.toLowerCase()) ||
      f.file_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.description?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="files-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">My Encrypted Files</h1>
          <p className="page-subtitle">Manage, decrypt, verify SHA-256 integrity, and share files</p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchFiles} title="Refresh">
            🔄 Refresh
          </button>
          <Link to="/upload" className="btn-primary">
            + Upload New File
          </Link>
        </div>
      </div>

      <div className="card-section" style={{ padding: "20px" }}>
        <input
          type="text"
          className="cyber-input"
          placeholder="🔍 Search files by name, description, or UUID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {error && (
        <div style={{ padding: "16px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "12px", color: "#fca5a5", marginBottom: "24px" }}>
          ⚠️ {error}
        </div>
      )}

      <div className="card-section">
        {loading ? (
          <div style={{ textAlign: "center", padding: "40px", color: "var(--text-secondary)" }}>
            Loading encrypted vault...
          </div>
        ) : filteredFiles.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px 24px" }}>
            <div style={{ fontSize: "40px", marginBottom: "12px" }}>📁</div>
            <h3 style={{ color: "#fff", marginBottom: "6px" }}>No encrypted files found</h3>
            <p style={{ color: "var(--text-secondary)", marginBottom: "20px" }}>
              Upload a file to encrypt it with AES-256-GCM authenticated encryption.
            </p>
            <Link to="/upload" className="btn-primary">
              Encrypt First File
            </Link>
          </div>
        ) : (
          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Size</th>
                  <th>Encryption & SHA-256 Checksum</th>
                  <th>Uploaded</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredFiles.map((file) => {
                  const verification = verificationResult[file.file_id];
                  return (
                    <tr key={file.file_id}>
                      <td>
                        <div style={{ fontWeight: "700", color: "#fff", display: "flex", alignItems: "center", gap: "8px" }}>
                          📄 {file.filename}
                        </div>
                        {file.description && (
                          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                            {file.description}
                          </div>
                        )}
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                          ID: {file.file_id}
                        </div>
                      </td>

                      <td>
                        <div style={{ fontWeight: "600" }}>{(file.file_size / 1024).toFixed(1)} KB</div>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          Enc: {file.encrypted_size} B
                        </div>
                      </td>

                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                          <span className="badge-tag badge-success">
                            {file.encryption_algorithm || "AES-256-GCM"}
                          </span>
                          {verification && (
                            <span
                              className={`badge-tag ${
                                verification.intact ? "badge-success" : "badge-critical"
                              }`}
                            >
                              {verification.intact ? "✓ INTACT" : "✗ TAMPERED"}
                            </span>
                          )}
                        </div>
                        <div className="hash-cell" title={file.sha256_hash}>
                          {file.sha256_hash ? `${file.sha256_hash.slice(0, 16)}...${file.sha256_hash.slice(-8)}` : "-"}
                        </div>
                      </td>

                      <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                        {new Date(file.uploaded_at).toLocaleString()}
                      </td>

                      <td style={{ textAlign: "right" }}>
                        <div style={{ display: "inline-flex", gap: "8px" }}>
                          <button
                            className="btn-secondary"
                            onClick={() => handleVerifyIntegrity(file.file_id)}
                            disabled={verifyingId === file.file_id}
                            title="Verify SHA-256 Integrity"
                          >
                            {verifyingId === file.file_id ? "Verifying..." : "🛡️ Verify"}
                          </button>

                          <button
                            className="btn-primary"
                            style={{ padding: "8px 14px", fontSize: "13px" }}
                            onClick={() => handleDownload(file.file_id, file.filename)}
                            title="Decrypt & Download"
                          >
                            ⬇️ Download
                          </button>

                          <button
                            className="btn-danger"
                            onClick={() => handleDelete(file.file_id)}
                            title="Delete File"
                          >
                            🗑️
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default MyFiles;