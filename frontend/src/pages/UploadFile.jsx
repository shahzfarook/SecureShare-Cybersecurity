import { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { LockIcon, UploadIcon, CheckIcon, AlertIcon } from "../components/Icons";

function UploadFile() {
  const [file, setFile] = useState(null);
  const [description, setDescription] = useState("");
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) {
      setError("Please select a file to encrypt and upload.");
      return;
    }

    setUploading(true);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);
    if (description) {
      formData.append("description", description);
    }

    try {
      let response;
      try {
        response = await axios.post("/api/files/upload", formData, {
          headers: { "Content-Type": "multipart/form-data" },
        });
      } catch {
        response = await axios.post("http://localhost:8001/api/files/upload", formData, {
          headers: { "Content-Type": "multipart/form-data" },
        });
      }
      setResult(response.data);
      setFile(null);
      setDescription("");
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || "Upload failed. Ensure the File Sharing API is running on port 8001.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="upload-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Encrypt & Upload File</h1>
          <p className="page-subtitle">Payloads are encrypted at rest using AES-256-GCM and signed with cryptographic SHA-256 digests</p>
        </div>
      </div>

      <div className="card-section">
        <form onSubmit={handleUpload}>
          <div
            className={`dropzone ${isDragging ? "active" : ""}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => document.getElementById("fileInput").click()}
          >
            <input
              id="fileInput"
              type="file"
              style={{ display: "none" }}
              onChange={handleFileChange}
            />

            <div style={{ display: "inline-flex", padding: "18px", borderRadius: "50%", background: "var(--accent-primary-subtle)", marginBottom: "16px", color: "var(--accent-primary)" }}>
              <LockIcon size={38} />
            </div>

            {file ? (
              <div>
                <h3 style={{ color: "var(--text-primary)", marginBottom: "6px", fontWeight: "800" }}>Selected: {file.name}</h3>
                <p style={{ color: "var(--accent-primary)", fontSize: "14px", fontWeight: "700" }}>
                  {(file.size / 1024).toFixed(2)} KB • Ready for AES-256 Encryption
                </p>
              </div>
            ) : (
              <div>
                <h3 style={{ color: "var(--text-primary)", marginBottom: "6px", fontWeight: "800" }}>
                  Drag & drop file here, or click to browse
                </h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
                  Supports all formats (.pdf, .docx, .png, .jpeg, .zip, .json, .log)
                </p>
              </div>
            )}
          </div>

          <div style={{ marginTop: "24px" }}>
            <label style={{ display: "block", fontSize: "13px", fontWeight: "700", color: "var(--text-primary)", marginBottom: "8px" }}>
              Optional Description / Classification
            </label>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g. Confidential Financial Audit Report"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {error && (
            <div style={{ marginTop: "16px", padding: "14px 18px", background: "var(--accent-rose-subtle)", border: "1px solid var(--accent-rose-border)", borderRadius: "12px", color: "var(--accent-rose)", fontSize: "13px", fontWeight: "600", display: "flex", alignItems: "center", gap: "8px" }}>
              <AlertIcon size={16} />
              <span>{error}</span>
            </div>
          )}

          <div style={{ marginTop: "24px", display: "flex", justifyContent: "flex-end" }}>
            <button type="submit" className="btn-primary" disabled={uploading || !file}>
              <UploadIcon size={16} />
              {uploading ? "Encrypting & Storing..." : "Encrypt & Store File"}
            </button>
          </div>
        </form>
      </div>

      {result && (
        <div className="card-section" style={{ border: "1px solid var(--accent-amber-border)", background: "var(--accent-amber-subtle)" }}>
          <div className="section-header">
            <div className="section-title" style={{ color: "var(--accent-amber)", display: "flex", alignItems: "center", gap: "8px" }}>
              <CheckIcon size={20} />
              <span>File Encrypted & Stored Successfully</span>
            </div>
            <Link to="/files" className="btn-secondary">
              View in Vault →
            </Link>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", marginTop: "16px" }}>
            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>File Name</div>
              <div style={{ fontWeight: "800", color: "var(--text-primary)", marginTop: "4px" }}>{result.filename}</div>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>File ID (UUID)</div>
              <div className="hash-cell" style={{ marginTop: "4px", fontSize: "11px" }}>{result.file_id}</div>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Encryption Standard</div>
              <div style={{ marginTop: "4px" }}>
                <span className="badge-tag badge-success">
                  {result.encryption_algorithm || "AES-256-GCM"}
                </span>
              </div>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Ciphertext Size</div>
              <div style={{ fontWeight: "700", color: "var(--text-primary)", marginTop: "4px" }}>
                {result.encrypted_size} bytes
              </div>
            </div>
          </div>

          <div style={{ marginTop: "20px" }}>
            <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "4px" }}>
              Cryptographic SHA-256 Digest
            </div>
            <div className="hash-cell" style={{ wordBreak: "break-all", fontSize: "12px" }}>
              {result.sha256_hash}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default UploadFile;