function UploadFile() {
  return (
    <div className="page-container">
      <div className="header-row">
        <div>
          <h1>Secure File Encryption & Upload</h1>
          <p className="page-subtitle">Files are encrypted end-to-end in your browser prior to storage.</p>
        </div>
      </div>

      <div className="card-panel" style={{ maxWidth: "650px" }}>
        <div style={{ border: "2px dashed #334155", borderRadius: "12px", padding: "40px", textAlign: "center", marginBottom: "20px", background: "#0f172a" }}>
          <div style={{ fontSize: "42px", marginBottom: "10px" }}>📤</div>
          <h3 style={{ marginBottom: "8px" }}>Drag & Drop file to encrypt</h3>
          <p style={{ color: "#94a3b8", fontSize: "14px", marginBottom: "15px" }}>Supported formats: PDF, DOCX, ZIP, IMAGES (Max 100MB)</p>
          <button className="btn-primary">Browse Files</button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "15px" }}>
          <div>
            <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "6px", color: "#cbd5e1" }}>
              Encryption Algorithm
            </label>
            <select className="select-filter" style={{ width: "100%" }} defaultValue="AES-256-GCM">
              <option value="AES-256-GCM">AES-256-GCM (NIST Recommended)</option>
              <option value="ChaCha20-Poly1305">ChaCha20-Poly1305 (High Performance)</option>
            </select>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "6px", color: "#cbd5e1" }}>
              Access Passphrase (Optional)
            </label>
            <input type="password" placeholder="Enter passphrase for additional key derivation..." className="search-input" style={{ width: "100%" }} />
          </div>

          <button className="btn-primary" style={{ width: "100%", justifyContent: "center", padding: "12px" }}>
            🔒 Encrypt and Store Securely
          </button>
        </div>
      </div>
    </div>
  );
}

export default UploadFile;