import { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";
import { LockIcon, AlertIcon, DownloadIcon, RefreshIcon } from "./Icons";
import { getApiUrl } from "../config/api";

function OtpDownloadModal({ file, onClose, onSuccess }) {
  const [otpCode, setOtpCode] = useState("");
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [timeLeft, setTimeLeft] = useState(300); // 5 minutes
  const inputRef = useRef(null);

  // Request download OTP when modal opens
  const requestOtp = useCallback(async () => {
    setLoading(true);
    setError(null);
    setOtpCode("");
    try {
      const userEmail = localStorage.getItem("secureshare_email") || "";
      const res = await axios.post(getApiUrl(`/api/files/request-download/${file.file_id}`), { email: userEmail });

      setRecipientEmail(res.data?.recipient_email || "your registered email");
      setTimeLeft(res.data?.expires_in_seconds || 300);
      setTimeout(() => inputRef.current?.focus(), 100);
    } catch (err) {
      setError(err.response?.data?.detail || err.response?.data?.error || "Failed to dispatch verification email.");
    } finally {
      setLoading(false);
    }
  }, [file]);

  useEffect(() => {
    if (file?.file_id) {
      requestOtp();
    }
  }, [file, requestOtp]);

  // Countdown timer
  useEffect(() => {
    if (timeLeft <= 0) return;
    const timer = setInterval(() => {
      setTimeLeft((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [timeLeft]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  const handleVerifyAndDownload = async (e) => {
    if (e) e.preventDefault();
    if (!otpCode || otpCode.trim().length !== 6) {
      setError("Please enter the complete 6-digit verification code.");
      return;
    }

    setVerifying(true);
    setError(null);

    try {
      const res = await axios.post(
        getApiUrl("/api/files/verify-download"),
        { file_id: file.file_id, otp_code: otpCode.trim() },
        { responseType: "blob" }
      );

      // Create download anchor and trigger browser download
      const blob = new Blob([res.data]);
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = file.filename || "decrypted_file";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(downloadUrl);

      if (onSuccess) onSuccess();
      onClose();
    } catch (err) {
      if (err.response?.data instanceof Blob) {
        // Read error JSON from blob response
        try {
          const errorText = await err.response.data.text();
          const errorJson = JSON.parse(errorText);
          setError(errorJson.detail || errorJson.error || "Verification failed. Invalid OTP code.");
        } catch {
          setError("Verification failed. Invalid or expired OTP code.");
        }
      } else {
        setError(err.response?.data?.detail || err.response?.data?.error || "Verification failed. Invalid OTP code.");
      }
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: "rgba(15, 23, 42, 0.65)",
        backdropFilter: "blur(6px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "20px",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "480px",
          background: "#ffffff",
          borderRadius: "20px",
          border: "1px solid var(--border-color)",
          boxShadow: "0 20px 40px -15px rgba(0,0,0,0.15)",
          overflow: "hidden",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: "22px 28px",
            borderBottom: "1px solid var(--border-color)",
            background: "linear-gradient(135deg, #faf5ff 0%, #ffffff 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div
              style={{
                width: "40px",
                height: "40px",
                borderRadius: "10px",
                background: "var(--accent-primary-subtle)",
                border: "1px solid rgba(126, 34, 206, 0.2)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <LockIcon size={20} color="var(--accent-primary)" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: "16px", fontWeight: "700", color: "var(--text-primary)" }}>
                2FA Email Verification
              </h3>
              <p style={{ margin: "2px 0 0", fontSize: "12px", color: "var(--text-muted)" }}>
                Authenticate file decryption access
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: "none",
              border: "none",
              fontSize: "18px",
              cursor: "pointer",
              color: "var(--text-muted)",
              padding: "4px 8px",
              borderRadius: "6px",
            }}
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "26px 28px" }}>
          {loading ? (
            <div style={{ textAlign: "center", padding: "36px 0", color: "var(--text-secondary)" }}>
              <div style={{ marginBottom: "12px" }}>
                <RefreshIcon size={28} color="var(--accent-primary)" />
              </div>
              <p style={{ fontWeight: "600", fontSize: "14px" }}>Sending verification code to your email...</p>
            </div>
          ) : (
            <form onSubmit={handleVerifyAndDownload}>
              <div style={{ textAlign: "center", marginBottom: "22px" }}>
                <p style={{ fontSize: "14px", color: "var(--text-secondary)", lineHeight: "1.5", margin: 0 }}>
                  A one-time verification code has been sent to:
                </p>
                <div
                  style={{
                    display: "inline-block",
                    background: "var(--accent-primary-subtle)",
                    border: "1px solid rgba(126, 34, 206, 0.2)",
                    color: "var(--accent-primary)",
                    padding: "4px 14px",
                    borderRadius: "9999px",
                    fontSize: "13px",
                    fontWeight: "700",
                    marginTop: "6px",
                  }}
                >
                  {recipientEmail}
                </div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
                  Target File: <strong>{file.filename}</strong>
                </div>
              </div>

              {error && (
                <div
                  style={{
                    padding: "12px 16px",
                    background: "var(--accent-rose-subtle)",
                    border: "1px solid var(--accent-rose-border)",
                    borderRadius: "12px",
                    color: "var(--accent-rose)",
                    fontSize: "13px",
                    fontWeight: "600",
                    marginBottom: "18px",
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <AlertIcon size={16} />
                  <span>{error}</span>
                </div>
              )}

              {/* 6-Digit Code Input */}
              <div style={{ marginBottom: "20px" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "12px",
                    fontWeight: "700",
                    color: "var(--text-primary)",
                    marginBottom: "8px",
                    textAlign: "center",
                    textTransform: "uppercase",
                    letterSpacing: "0.5px",
                  }}
                >
                  Enter 6-Digit Passcode
                </label>

                <input
                  ref={inputRef}
                  type="text"
                  maxLength={6}
                  placeholder="------"
                  value={otpCode}
                  onChange={(e) => {
                    const val = e.target.value.replace(/\D/g, "");
                    setOtpCode(val);
                    setError(null);
                  }}
                  style={{
                    width: "100%",
                    height: "56px",
                    textAlign: "center",
                    fontSize: "30px",
                    fontWeight: "800",
                    fontFamily: "'Courier New', Courier, monospace",
                    letterSpacing: "14px",
                    borderRadius: "14px",
                    border: "2px solid var(--border-color)",
                    background: "var(--bg-surface)",
                    color: "var(--text-primary)",
                    outline: "none",
                    boxShadow: "inset 0 2px 4px rgba(0,0,0,0.03)",
                  }}
                  required
                  autoComplete="one-time-code"
                />
              </div>

              {/* Countdown and Resend Row */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: "12px",
                  color: "var(--text-secondary)",
                  marginBottom: "24px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <span>Code Expires In:</span>
                  <strong style={{ color: timeLeft < 60 ? "var(--accent-rose)" : "var(--accent-primary)" }}>
                    {formatTime(timeLeft)}
                  </strong>
                </div>

                <button
                  type="button"
                  onClick={requestOtp}
                  disabled={loading || verifying}
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--accent-primary)",
                    fontWeight: "700",
                    cursor: "pointer",
                    fontSize: "12px",
                    textDecoration: "underline",
                  }}
                >
                  Resend Code
                </button>
              </div>

              {/* Actions */}
              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={onClose}
                  style={{ flex: 1, padding: "12px" }}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="btn-primary"
                  disabled={verifying || otpCode.length !== 6 || timeLeft <= 0}
                  style={{ flex: 2, padding: "12px" }}
                >
                  {verifying ? (
                    "Verifying & Decrypting..."
                  ) : (
                    <>
                      <DownloadIcon size={16} /> Verify &amp; Download
                    </>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

export default OtpDownloadModal;
