function SharedFiles() {
  const sharedItems = [
    { id: 1, name: "soc2_compliance_matrix.xlsx.enc", sharedBy: "sec_officer@secureshare.local", expires: "In 2 days", permissions: "Read-Only" },
    { id: 2, name: "threat_intel_feed_2026.json.enc", sharedBy: "anfas@secureshare.local", expires: "In 12 hours", permissions: "Read / Decrypt" }
  ];

  return (
    <div className="page-container">
      <div className="header-row">
        <div>
          <h1>Shared Encrypted Vault</h1>
          <p className="page-subtitle">Access files securely shared with time-limited cryptographic tokens.</p>
        </div>
      </div>

      <div className="card-panel">
        <div className="table-responsive">
          <table className="custom-table">
            <thead>
              <tr>
                <th>File Name</th>
                <th>Shared By</th>
                <th>Expiration</th>
                <th>Permissions</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sharedItems.map((item) => (
                <tr key={item.id}>
                  <td><span className="code-badge">🔗 {item.name}</span></td>
                  <td>{item.sharedBy}</td>
                  <td><span className="status-badge badge-medium" style={{ fontSize: "11px" }}>⏳ {item.expires}</span></td>
                  <td><span className="status-badge badge-secure" style={{ fontSize: "11px" }}>{item.permissions}</span></td>
                  <td>
                    <button className="btn-secondary" style={{ padding: "5px 10px", fontSize: "12px" }}>
                      Access File
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

export default SharedFiles;