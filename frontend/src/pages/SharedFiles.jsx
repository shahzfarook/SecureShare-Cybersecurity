import { useState, useEffect } from "react";
import axios from "axios";
import { CopyIcon, CheckIcon, FileIcon, DownloadIcon } from "../components/Icons";
import OtpDownloadModal from "../components/OtpDownloadModal";
import { getApiUrl } from "../config/api";

function SharedFiles() {
  const [files, setFiles] = useState([]);
  const [copiedId, setCopiedId] = useState(null);
  const [selectedDownloadFile, setSelectedDownloadFile] = useState(null);

  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const res = await axios.get(getApiUrl("/api/files/list"));
        setFiles(res.data || []);
      } catch (e) {
        console.log("Failed to load files:", e.message);
      }
    };
    fetchFiles();
  }, []);

  const handleCopyLink = (fileId) => {
    const downloadUrl = getApiUrl(`/api/files/download/${fileId}`);
    navigator.clipboard.writeText(downloadUrl);
    setCopiedId(fileId);
    setTimeout(() => setCopiedId(null), 2500);
  };

  return (
    <div className="shared-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Encrypted File Sharing & Distribution</h1>
          <p className="page-subtitle">Generate secure direct download links with automated cryptographic SHA-256 integrity verification</p>
        </div>
      </div>

      <div className="card-section">
        <div className="section-header">
          <div className="section-title">
            <span>Shareable Encrypted Vault Links</span>
          </div>
        </div>

        {files.length === 0 ? (
          <div style={{ textAlign: "center", padding: "48px", color: "var(--text-secondary)" }}>
            No files available for sharing. Upload a file first in <strong>Upload & Encrypt</strong>.
          </div>
        ) : (
          <div className="cyber-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Encryption & Integrity</th>
                  <th>Direct Vault Link</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file) => (
                  <tr key={file.file_id}>
                    <td>
                      <div style={{ fontWeight: "800", color: "var(--text-primary)", display: "flex", alignItems: "center", gap: "8px" }}>
                        <FileIcon size={16} color="var(--accent-primary)" />
                        <span>{file.filename}</span>
                      </div>
                      <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "2px" }}>
                        {(file.file_size / 1024).toFixed(1)} KB • Uploaded {new Date(file.uploaded_at).toLocaleDateString()}
                      </div>
                    </td>

                    <td>
                      <span className="badge-tag badge-success" style={{ marginRight: "8px" }}>
                        AES-256-GCM
                      </span>
                      <span className="hash-cell" style={{ fontSize: "11px" }}>
                        SHA-256: {file.sha256_hash?.slice(0, 10)}...
                      </span>
                    </td>

                    <td>
                      <input
                        type="text"
                        readOnly
                        value={getApiUrl(`/api/files/download/${file.file_id}`)}
                        className="cyber-input"
                        style={{ fontSize: "12px", padding: "8px 12px", color: "var(--accent-primary)", width: "300px", fontWeight: "600" }}
                        onClick={(e) => e.target.select()}
                      />
                    </td>

                    <td style={{ textAlign: "right" }}>
                      <div style={{ display: "inline-flex", gap: "8px" }}>
                        <button
                          className="btn-secondary"
                          style={{ padding: "8px 14px", fontSize: "12px" }}
                          onClick={() => handleCopyLink(file.file_id)}
                          title="Copy download link"
                        >
                          {copiedId === file.file_id ? (
                            <>
                              <CheckIcon size={14} /> Copied
                            </>
                          ) : (
                            <>
                              <CopyIcon size={14} /> Copy Link
                            </>
                          )}
                        </button>

                        <button
                          className="btn-primary"
                          style={{ padding: "8px 14px", fontSize: "12px" }}
                          onClick={() => setSelectedDownloadFile(file)}
                          title="Verify 2FA OTP & Download"
                        >
                          <DownloadIcon size={14} /> Download
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 2FA Email OTP Download Verification Modal */}
      {selectedDownloadFile && (
        <OtpDownloadModal
          file={selectedDownloadFile}
          onClose={() => setSelectedDownloadFile(null)}
        />
      )}
    </div>
  );
}

export default SharedFiles;