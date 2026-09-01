function MyFiles() {
  const sampleFiles = [
    { id: 1, name: "financial_audit_q3_2026.pdf.enc", size: "4.2 MB", algorithm: "AES-256-GCM", date: "2026-08-30", status: "Encrypted" },
    { id: 2, name: "infrastructure_keys_backup.tar.gz.enc", size: "12.8 MB", algorithm: "ChaCha20-Poly1305", date: "2026-08-28", status: "Encrypted" },
    { id: 3, name: "penetration_test_report.docx.enc", size: "1.1 MB", algorithm: "AES-256-GCM", date: "2026-08-25", status: "Encrypted" }
  ];

  return (
    <div className="page-container">
      <div className="header-row">
        <div>
          <h1>Encrypted File Vault</h1>
          <p className="page-subtitle">Zero-knowledge client-side encrypted files stored securely.</p>
        </div>
      </div>

      <div className="card-panel">
        <div className="table-responsive">
          <table className="custom-table">
            <thead>
              <tr>
                <th>File Name</th>
                <th>Encryption</th>
                <th>Size</th>
                <th>Upload Date</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sampleFiles.map((f) => (
                <tr key={f.id}>
                  <td><span className="code-badge">🔒 {f.name}</span></td>
                  <td><span className="status-badge badge-low">{f.algorithm}</span></td>
                  <td>{f.size}</td>
                  <td>{f.date}</td>
                  <td><span className="status-badge badge-secure">{f.status}</span></td>
                  <td>
                    <button className="btn-secondary" style={{ padding: "5px 10px", fontSize: "12px" }}>
                      Decrypt & Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default MyFiles;