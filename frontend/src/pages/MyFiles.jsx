import { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { FileIcon, RefreshIcon, UploadIcon, DownloadIcon, TrashIcon, ShieldIcon, CheckIcon, AlertIcon, CopyIcon } from "../components/Icons";
import OtpDownloadModal from "../components/OtpDownloadModal";
import { getApiUrl } from "../config/api";

function MyFiles() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationResult, setVerificationResult] = useState({});
  const [activeModalData, setActiveModalData] = useState(null);
  const [selectedDownloadFile, setSelectedDownloadFile] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [bannerNotice, setBannerNotice] = useState(null);

  const fetchFiles = async () => {
    try {
      setLoading(true);
      const res = await axios.get(getApiUrl("/api/files/list"));
      setFiles(res.data || []);
      setError(null);
    } catch {
      setError("Could not connect to SecureShare API. Make sure the backend service is running.");
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
      const res = await axios.get(getApiUrl(`/api/files/verify/${fileId}`));
      
      const vData = res.data;
      setVerificationResult((prev) => ({ ...prev, [fileId]: vData }));
      setActiveModalData(vData);
      setBannerNotice({
        type: vData.intact ? "success" : "error",
        text: `Cryptographic Integrity Verification for "${vData.filename || fileId}": ${vData.intact ? "PASSED (SHA-256 Checksum Match)" : "FAILED (Tampered)"}`,
      });
    } catch (err) {
      alert("Verification failed: " + (err.response?.data?.detail || err.message));
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm("Are you sure you want to securely delete this encrypted file from the vault?")) return;

    try {
      try {
        await axios.delete(getApiUrl(`/api/files/${fileId}`));
      } catch {
        await axios.post(getApiUrl(`/api/files/delete/${fileId}`));
      }
      setFiles((prev) => prev.filter((f) => f.file_id !== fileId));
      if (activeModalData?.file_id === fileId) {
        setActiveModalData(null);
      }
      setBannerNotice({
        type: "success",
        text: "Encrypted file deleted securely from vault.",
      });
      setTimeout(fetchFiles, 200);
    } catch (err) {
      alert("Delete failed: " + (err.response?.data?.detail || err.message));
    }
  };

  const handleDownload = (file) => {
    const targetFile = typeof file === "object" ? file : files.find((f) => f.file_id === file) || { file_id: file, filename: activeModalData?.filename || "vault_file" };
    setSelectedDownloadFile(targetFile);
  };

  const handleCopyHash = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
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
          <h1 className="page-title">Encrypted File Vault</h1>
          <p className="page-subtitle">Manage, decrypt, verify SHA-256 integrity, and share files at rest</p>
        </div>

        <div style={{ display: "flex", gap: "12px" }}>
          <button className="btn-secondary" onClick={fetchFiles} title="Refresh Vault">
            <RefreshIcon size={16} /> Refresh
          </button>
          <Link to="/upload" className="btn-primary">
            <UploadIcon size={16} /> Upload New File
          </Link>
        </div>
      </div>

      {bannerNotice && (
        <div
          style={{
            padding: "16px 20px",
            background: bannerNotice.type === "success" ? "var(--accent-amber-subtle)" : "var(--accent-rose-subtle)",
            border: `1px solid ${bannerNotice.type === "success" ? "var(--accent-amber-border)" : "var(--accent-rose-border)"}`,
            borderRadius: "14px",
            color: bannerNotice.type === "success" ? "var(--accent-amber)" : "var(--accent-rose)",
            marginBottom: "24px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontWeight: "700",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {bannerNotice.type === "success" ? <CheckIcon size={20} /> : <AlertIcon size={20} />}
            <span>{bannerNotice.text}</span>
          </div>
          <button
            style={{ background: "none", border: "none", color: "inherit", cursor: "pointer", fontSize: "16px" }}
            onClick={() => setBannerNotice(null)}
          >
            ✕
          </button>
        </div>
      )}

      <div className="card-section" style={{ padding: "20px" }}>
        <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
          <input
            type="text"
            className="cyber-input"
            placeholder="Search vault by filename, classification, or UUID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {error && (
        <div style={{ padding: "16px 20px", background: "var(--accent-rose-subtle)", border: "1px solid var(--accent-rose-border)", borderRadius: "14px", color: "var(--accent-rose)", marginBottom: "24px", fontWeight: "600" }}>
          {error}
        </div>
      )}

      <div className="card-section">
        {loading ? (
          <div style={{ textAlign: "center", padding: "48px", color: "var(--text-secondary)" }}>
            Loading encrypted vault...
          </div>
        ) : filteredFiles.length === 0 ? (
          <div style={{ textAlign: "center", padding: "52px 24px" }}>
            <div style={{ display: "inline-flex", padding: "16px", borderRadius: "50%", background: "var(--accent-primary-subtle)", marginBottom: "16px" }}>
              <FileIcon size={36} color="var(--accent-primary)" />
            </div>
            <h3 style={{ color: "var(--text-primary)", marginBottom: "6px", fontWeight: "800" }}>No encrypted files found</h3>
            <p style={{ color: "var(--text-secondary)", marginBottom: "22px" }}>
              Upload a file to encrypt it with AES-256-GCM authenticated encryption.
            </p>
            <Link to="/upload" className="btn-primary">
              <UploadIcon size={16} /> Encrypt First File
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
                        <div style={{ fontWeight: "800", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                          <FileIcon size={16} color="var(--accent-primary)" />
                          <span>{file.filename}</span>
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
                        <div style={{ fontWeight: "700", color: "var(--text-primary)" }}>{(file.file_size / 1024).toFixed(1)} KB</div>
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
                              style={{ cursor: "pointer" }}
                              onClick={() => setActiveModalData(verification)}
                              title="Click to view full cryptographic proof"
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
                            className={verification?.intact ? "btn-secondary" : "btn-secondary"}
                            onClick={() => handleVerifyIntegrity(file.file_id)}
                            disabled={verifyingId === file.file_id}
                            title="Verify SHA-256 Cryptographic Integrity"
                            style={{
                              fontSize: "12px",
                              padding: "6px 12px",
                              borderColor: verification?.intact ? "var(--accent-amber)" : undefined,
                              color: verification?.intact ? "var(--accent-amber)" : undefined,
                            }}
                          >
                            <ShieldIcon size={14} />
                            {verifyingId === file.file_id ? (
                              "Verifying..."
                            ) : verification?.intact ? (
                              "Verified (Intact)"
                            ) : (
                              "Verify"
                            )}
                          </button>

                          <button
                            className="btn-primary"
                            style={{ padding: "6px 14px", fontSize: "12px" }}
                            onClick={() => handleDownload(file.file_id)}
                            title="Decrypt & Download"
                          >
                            <DownloadIcon size={14} /> Download
                          </button>

                          <button
                            className="btn-danger"
                            onClick={() => handleDelete(file.file_id)}
                            title="Delete File"
                            style={{ padding: "6px 10px" }}
                          >
                            <TrashIcon size={14} />
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

      {/* Cryptographic Integrity Verification Modal */}
      {activeModalData && (
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
          onClick={() => setActiveModalData(null)}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "680px",
              background: "#ffffff",
              borderRadius: "20px",
              border: "1px solid var(--border-color)",
              boxShadow: "var(--shadow-lg)",
              overflow: "hidden",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: "22px 28px",
                borderBottom: "1px solid var(--border-color)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: activeModalData.intact ? "var(--accent-amber-subtle)" : "var(--accent-rose-subtle)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <div
                  style={{
                    width: "42px",
                    height: "42px",
                    borderRadius: "12px",
                    background: activeModalData.intact ? "var(--accent-amber)" : "var(--accent-rose)",
                    color: "#ffffff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  {activeModalData.intact ? <CheckIcon size={24} /> : <AlertIcon size={24} />}
                </div>
                <div>
                  <h3 style={{ fontSize: "18px", fontWeight: "800", color: "var(--text-primary)" }}>
                    {activeModalData.intact ? "Cryptographic Integrity Verified" : "Integrity Verification Failed"}
                  </h3>
                  <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "2px" }}>
                    File: <strong>{activeModalData.filename}</strong>
                  </p>
                </div>
              </div>

              <button
                style={{
                  background: "none",
                  border: "none",
                  fontSize: "20px",
                  color: "var(--text-muted)",
                  cursor: "pointer",
                  padding: "4px 8px",
                }}
                onClick={() => setActiveModalData(null)}
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: "26px 28px", display: "flex", flexDirection: "column", gap: "18px" }}>
              <div
                style={{
                  background: "var(--bg-surface)",
                  padding: "16px 20px",
                  borderRadius: "14px",
                  border: "1px solid var(--border-color)",
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                  gap: "14px",
                  fontSize: "13px",
                }}
              >
                <div>
                  <span style={{ color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase", fontWeight: "700" }}>
                    Cipher Standard
                  </span>
                  <div style={{ fontWeight: "800", color: "var(--accent-primary)", marginTop: "2px" }}>
                    {activeModalData.encryption_algorithm || "AES-256-GCM"}
                  </div>
                </div>

                <div>
                  <span style={{ color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase", fontWeight: "700" }}>
                    Decryption Authentication
                  </span>
                  <div style={{ fontWeight: "800", color: activeModalData.intact ? "var(--accent-amber)" : "var(--accent-rose)", marginTop: "2px" }}>
                    {activeModalData.intact ? "Authenticated (Tag OK)" : "Authentication Failed"}
                  </div>
                </div>

                <div>
                  <span style={{ color: "var(--text-muted)", fontSize: "11px", textTransform: "uppercase", fontWeight: "700" }}>
                    Plaintext Size
                  </span>
                  <div style={{ fontWeight: "800", color: "var(--text-primary)", marginTop: "2px" }}>
                    {(activeModalData.file_size / 1024).toFixed(1)} KB
                  </div>
                </div>
              </div>

              {/* Hashes Comparison */}
              <div>
                <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-primary)", marginBottom: "6px" }}>
                  Expected Stored SHA-256 Digest:
                </div>
                <div
                  className="hash-cell"
                  style={{
                    width: "100%",
                    padding: "10px 14px",
                    fontSize: "12px",
                    wordBreak: "break-all",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <span>{activeModalData.stored_sha256}</span>
                  <button
                    style={{ background: "none", border: "none", cursor: "pointer", color: "var(--accent-primary)", padding: "0 4px" }}
                    onClick={() => handleCopyHash(activeModalData.stored_sha256)}
                    title="Copy SHA-256 Hash"
                  >
                    <CopyIcon size={14} />
                  </button>
                </div>
              </div>

              <div>
                <div style={{ fontSize: "12px", fontWeight: "700", color: "var(--text-primary)", marginBottom: "6px" }}>
                  Recomputed Ciphertext SHA-256 Digest:
                </div>
                <div
                  className="hash-cell"
                  style={{
                    width: "100%",
                    padding: "10px 14px",
                    fontSize: "12px",
                    wordBreak: "break-all",
                    background: activeModalData.intact ? "var(--accent-amber-subtle)" : "var(--accent-rose-subtle)",
                    borderColor: activeModalData.intact ? "var(--accent-amber-border)" : "var(--accent-rose-border)",
                    color: activeModalData.intact ? "var(--accent-amber)" : "var(--accent-rose)",
                  }}
                >
                  <span>{activeModalData.computed_sha256 || "Decryption failed / corrupted"}</span>
                </div>
              </div>

              <div style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: "1.5" }}>
                {activeModalData.status_message}
              </div>
            </div>

            {/* Modal Footer */}
            <div
              style={{
                padding: "18px 28px",
                borderTop: "1px solid var(--border-color)",
                background: "#f8fafc",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Verified at {new Date(activeModalData.checked_at).toLocaleTimeString()}
              </div>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  className="btn-secondary"
                  onClick={() => handleCopyHash(activeModalData.stored_sha256)}
                  style={{ fontSize: "13px" }}
                >
                  {copiedHash ? "✓ Copied" : "Copy Hash"}
                </button>

                <button
                  className="btn-primary"
                  onClick={() => handleDownload(activeModalData.file_id)}
                  style={{ fontSize: "13px" }}
                >
                  <DownloadIcon size={14} /> Download File
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2FA Email OTP Download Verification Modal */}
      {selectedDownloadFile && (
        <OtpDownloadModal
          file={selectedDownloadFile}
          onClose={() => setSelectedDownloadFile(null)}
          onSuccess={() => {
            setBannerNotice({
              type: "success",
              text: `Decrypted and downloaded "${selectedDownloadFile.filename}" with verified 2FA OTP.`,
            });
          }}
        />
      )}
    </div>
  );
}

export default MyFiles;