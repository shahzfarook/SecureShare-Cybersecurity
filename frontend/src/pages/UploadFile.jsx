import { useState } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

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
      const response = await axios.post("http://localhost:8001/api/files/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setResult(response.data);
      setFile(null);
      setDescription("");
    } catch (err) {
      setError(err.response?.data?.detail || "Upload failed. Ensure the File Sharing API is running on port 8001.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="upload-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Encrypt & Upload File</h1>
          <p className="page-subtitle">Payloads are encrypted at rest with AES-256-GCM and hashed with SHA-256</p>
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

            <div className="dropzone-icon">🔒</div>

            {file ? (
              <div>
                <h3 style={{ color: "#fff", marginBottom: "6px" }}>Selected: {file.name}</h3>
                <p style={{ color: "var(--accent-cyan)", fontSize: "14px" }}>
                  {(file.size / 1024).toFixed(2)} KB • Ready for AES-256 Encryption
                </p>
              </div>
            ) : (
              <div>
                <h3 style={{ color: "#fff", marginBottom: "6px" }}>
                  Drag & Drop file here, or click to browse
                </h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
                  Supports all formats (.pdf, .docx, .png, .zip, .json, .log)
                </p>
              </div>
            )}
          </div>

          <div style={{ marginTop: "24px" }}>
            <label style={{ display: "block", fontSize: "13px", fontWeight: "600", color: "var(--text-secondary)", marginBottom: "8px" }}>
              Optional Description / Classification
            </label>
            <input
              type="text"
              className="cyber-input"
              placeholder="e.g. Confidential Q3 Incident Report"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {error && (
            <div style={{ marginTop: "16px", padding: "12px 16px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", color: "#fca5a5", fontSize: "13px" }}>
              ⚠️ {error}
            </div>
          )}

          <div style={{ marginTop: "24px", display: "flex", justifyContent: "flex-end" }}>
            <button type="submit" className="btn-primary" disabled={uploading || !file}>
              {uploading ? "Encrypting & Storing..." : "🔐 Encrypt & Upload"}
            </button>
          </div>
        </form>
      </div>

      {result && (
        <div className="card-section" style={{ border: "1px solid rgba(16, 185, 129, 0.4)", background: "rgba(16, 185, 129, 0.05)" }}>
          <div className="section-header">
            <div className="section-title" style={{ color: "var(--accent-green)" }}>
              ✅ File Encrypted & Stored Successfully
            </div>
            <Link to="/files" className="btn-secondary">
              View in My Files →
            </Link>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "16px", marginTop: "16px" }}>
            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>File Name</div>
              <div style={{ fontWeight: "700", color: "#fff", marginTop: "4px" }}>{result.filename}</div>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>File ID (UUID)</div>
              <div className="hash-cell" style={{ marginTop: "4px", fontSize: "11px" }}>{result.file_id}</div>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Encryption Standard</div>
              <span className="badge-tag badge-success" style={{ marginTop: "4px" }}>
                {result.encryption_algorithm || "AES-256-GCM"}
              </span>
            </div>

            <div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>Ciphertext Size</div>
              <div style={{ fontWeight: "600", color: "var(--text-primary)", marginTop: "4px" }}>
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