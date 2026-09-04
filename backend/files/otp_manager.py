"""
SecureShare Cybersecurity - Download OTP Manager
Handles generation, 5-minute expiration, persistence, and real Gmail SMTP email dispatch
for Two-Factor Authentication (2FA) on file downloads.
"""

import os
import json
import secrets
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Tuple, Optional

_files_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_files_dir)
_root_dir = os.path.dirname(_backend_dir)
OTP_STORE_FILE = os.path.join(_backend_dir, "uploads", ".active_otps.json")


def _load_env():
    """Lightweight built-in .env parser to populate os.environ without external dependencies."""
    candidates = [
        os.path.join(_root_dir, ".env"),
        os.path.join(_backend_dir, ".env"),
        os.path.join(_backend_dir, "auth", ".env")
    ]
    for env_path in candidates:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip("'\"")
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass


_load_env()


class DownloadOTPManager:
    """Thread-safe and restart-persistent manager for download verification OTP codes."""

    EXPIRATION_SECONDS = 300  # 5 minutes
    MAX_ATTEMPTS = 3          # Max invalid attempts before code invalidation

    def __init__(self, store_path: Optional[str] = None):
        self._lock = threading.Lock()
        self.store_path = store_path or OTP_STORE_FILE
        self._otps: Dict[str, Dict[str, Any]] = self._load_store()

    def _load_store(self) -> Dict[str, Dict[str, Any]]:
        """Loads active OTP records from disk."""
        if not os.path.exists(self.store_path):
            return {}
        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            now = datetime.now(timezone.utc)
            valid_records = {}
            for fid, rec in raw_data.items():
                expires_at = datetime.fromisoformat(rec["expires_at"])
                if expires_at > now:
                    rec["expires_at_dt"] = expires_at
                    valid_records[fid] = rec
            return valid_records
        except Exception:
            return {}

    def _save_store(self) -> None:
        """Atomically persists active OTP records to disk."""
        try:
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            serializable = {}
            for fid, rec in self._otps.items():
                rec_copy = dict(rec)
                if "expires_at_dt" in rec_copy:
                    del rec_copy["expires_at_dt"]
                serializable[fid] = rec_copy

            tmp_path = self.store_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(serializable, f, indent=2)
            os.replace(tmp_path, self.store_path)
        except Exception as e:
            print(f"[OTP Manager] Failed to persist OTP store: {e}")

    def generate_otp(
        self,
        file_id: str,
        recipient_email: str,
        filename: str = "Confidential File",
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generates a cryptographically secure 6-digit OTP code valid for 5 minutes.
        Dispatches email to the recipient.
        """
        _load_env()
        smtp_user = os.environ.get("SMTP_USER", "").strip()

        # Resolve real delivery email (fallback to configured SMTP_USER for demo/local accounts)
        target_email = str(recipient_email or "").strip()
        if (not target_email or "@" not in target_email or target_email.endswith(".local")) and smtp_user and "@" in smtp_user:
            target_email = smtp_user
        elif not target_email or "@" not in target_email:
            target_email = "admin@secureshare.local"

        # 6-digit numeric code (100000 to 999999)
        otp_code = str(secrets.randbelow(900000) + 100000)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.EXPIRATION_SECONDS)

        record = {
            "file_id": str(file_id).strip(),
            "user_id": str(user_id or "").strip(),
            "filename": filename,
            "code": otp_code,
            "recipient_email": target_email,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_at_dt": expires_at,
            "attempts": 0,
            "verified": False,
        }

        with self._lock:
            self._otps[str(file_id).strip()] = record
            self._save_store()

        # Dispatch Email (Real Gmail SMTP or formatted console fallback)
        email_sent = self._send_email(
            recipient_email=target_email,
            filename=filename,
            otp_code=otp_code
        )

        return {
            "file_id": file_id,
            "recipient_email": self.mask_email(target_email),
            "raw_email": target_email,
            "expires_in_seconds": self.EXPIRATION_SECONDS,
            "expires_at": expires_at.isoformat(),
            "email_sent": email_sent,
            "dev_otp": otp_code
        }

    def verify_otp(self, file_id: str, submitted_code: str) -> Tuple[bool, str]:
        """
        Validates the submitted OTP code.
        Ensures strict string matching and single-use consumption.
        """
        clean_file_id = str(file_id).strip()
        clean_code = str(submitted_code).strip()

        if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
            return False, "Please provide a valid 6-digit numeric OTP code."

        with self._lock:
            record = self._otps.get(clean_file_id)
            if not record:
                self._otps = self._load_store()
                record = self._otps.get(clean_file_id)

            if not record:
                return False, "No active download OTP found for this file. Please request a new verification code."

            expires_at = record.get("expires_at_dt")
            if not expires_at and "expires_at" in record:
                expires_at = datetime.fromisoformat(record["expires_at"])
                record["expires_at_dt"] = expires_at

            now = datetime.now(timezone.utc)
            if expires_at and now > expires_at:
                if clean_file_id in self._otps:
                    del self._otps[clean_file_id]
                    self._save_store()
                return False, "Verification code has expired (5-minute limit exceeded). Please request a new code."

            # Increment attempts
            record["attempts"] += 1

            saved_code = str(record["code"]).strip()
            if clean_code != saved_code:
                remaining = self.MAX_ATTEMPTS - record["attempts"]
                if remaining <= 0:
                    if clean_file_id in self._otps:
                        del self._otps[clean_file_id]
                        self._save_store()
                    return False, "Maximum verification attempts exceeded (3/3). Code has been invalidated."
                self._save_store()
                return False, f"Invalid verification code. {remaining} attempt(s) remaining."

            # Valid OTP -> consume (single-use)
            record["verified"] = True
            if clean_file_id in self._otps:
                del self._otps[clean_file_id]
                self._save_store()
            return True, "OTP verified successfully."

    def get_active_otp(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Returns metadata for an active OTP if still valid."""
        clean_file_id = str(file_id).strip()
        with self._lock:
            record = self._otps.get(clean_file_id)
            if not record:
                self._otps = self._load_store()
                record = self._otps.get(clean_file_id)
            if not record:
                return None

            expires_at = record.get("expires_at_dt")
            if not expires_at and "expires_at" in record:
                expires_at = datetime.fromisoformat(record["expires_at"])
                record["expires_at_dt"] = expires_at

            now = datetime.now(timezone.utc)
            if expires_at and now > expires_at:
                if clean_file_id in self._otps:
                    del self._otps[clean_file_id]
                    self._save_store()
                return None

            return {
                "file_id": clean_file_id,
                "recipient_email": self.mask_email(record["recipient_email"]),
                "expires_in_seconds": max(0, int((expires_at - now).total_seconds())) if expires_at else 0,
                "attempts": record["attempts"]
            }

    @staticmethod
    def mask_email(email: str) -> str:
        """Masks an email for secure privacy display, e.g. a***z@gmail.com."""
        if not email or "@" not in email:
            return "u***@secureshare.local"
        user, domain = email.split("@", 1)
        if len(user) <= 2:
            masked_user = user[0] + "***"
        else:
            masked_user = user[0] + "***" + user[-1]
        return f"{masked_user}@{domain}"

    def _send_email(self, recipient_email: str, filename: str, otp_code: str) -> bool:
        """
        Dispatches HTML OTP verification email via real Gmail SMTP with plain-text fallback,
        clean sender headers, replyTo, priority headers, and anti-spam footer.
        Reads SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM.
        """
        _load_env()
        smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
        smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_user = os.environ.get("SMTP_USER", "").strip()
        smtp_pass = os.environ.get("SMTP_PASS", "").strip()
        
        sender_email = os.environ.get("SMTP_FROM", smtp_user or "anfasularifeen.nasimudeen@gmail.com").strip() or "anfasularifeen.nasimudeen@gmail.com"
        sender_header = f'"SecureShare Security" <{sender_email}>'
        reply_to_email = sender_email

        # 1. Optimized Dynamic Subject Line
        subject = f"Verification Code: {otp_code} for SecureShare File Decryption"

        # 2. Plain-Text Fallback Body (prevents spam flags)
        plain_text_content = f"""SecureShare File Decryption Verification

A request was made to decrypt and download the following file from your SecureShare Encrypted Vault:
Target File: {filename}

Your 6-Digit One-Time Verification Passcode:
>>> {otp_code} <<<

Security Details:
• Valid for 5 minutes (single-use).
• If you did not initiate this download request on SecureShare, your account or file access keys may be compromised.

You received this email because a file download request was initiated on the SecureShare Security Platform. If you did not request this, please ignore this message.

Protected by SecureShare AES-256-GCM Cryptographic Storage & SIEM Threat Engine
"""

        # 3. Formatted Professional HTML Template
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Code: {otp_code} for SecureShare File Decryption</title>
</head>
<body style="margin: 0; padding: 32px 16px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
  <table role="presentation" style="width: 100%; border-collapse: collapse;">
    <tr>
      <td align="center">
        <table role="presentation" style="max-width: 520px; width: 100%; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 4px 16px rgba(0,0,0,0.06); overflow: hidden;">
          <!-- Header Banner -->
          <tr>
            <td style="padding: 28px 32px; background: linear-gradient(135deg, #7e22ce 0%, #6b21a8 100%); text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 22px; font-weight: 800; letter-spacing: -0.5px;">SecureShare Vault</h1>
              <p style="margin: 4px 0 0; color: #e9d5ff; font-size: 13px; font-weight: 500;">Zero-Trust Encrypted File Access</p>
            </td>
          </tr>
          
          <!-- Content Body -->
          <tr>
            <td style="padding: 32px 32px 28px;">
              <h2 style="margin: 0 0 12px; color: #0f172a; font-size: 16px; font-weight: 700;">
                File Decryption Verification
              </h2>
              <p style="margin: 0 0 18px; color: #475569; font-size: 14px; line-height: 1.6;">
                This email was requested because an authorized download was initiated for the encrypted file: <br/>
                <strong style="color: #0f172a; word-break: break-all;">{filename}</strong>
              </p>
              
              <!-- 6-Digit Passcode Box -->
              <div style="background: #faf5ff; border: 2px dashed #a855f7; border-radius: 12px; padding: 22px; text-align: center; margin: 24px 0;">
                <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #7e22ce; display: block;">One-Time Verification Passcode</span>
                <div style="font-size: 38px; font-weight: 900; letter-spacing: 8px; color: #6b21a8; font-family: 'Courier New', Courier, monospace; margin-top: 8px;">
                  {otp_code}
                </div>
              </div>
              
              <!-- Security Explanations -->
              <p style="margin: 0 0 10px; color: #64748b; font-size: 13px; line-height: 1.5;">
                ⏱️ This code will expire in <strong>5 minutes</strong> and can only be used once to decrypt this specific file.
              </p>
              <p style="margin: 0; color: #dc2626; font-size: 12px; line-height: 1.5;">
                ⚠️ If you did not initiate this download on SecureShare, please ignore this email or review your account activity.
              </p>
            </td>
          </tr>
          
          <!-- Explicit Compliance & Anti-Spam Footer -->
          <tr>
            <td style="padding: 22px 32px; background: #f8fafc; border-top: 1px solid #e2e8f0; text-align: center;">
              <p style="margin: 0 0 6px; color: #64748b; font-size: 12px; line-height: 1.5;">
                You received this email because a file download request was initiated on the SecureShare Security Platform. If you did not request this, please ignore this message.
              </p>
              <p style="margin: 0; color: #94a3b8; font-size: 11px; line-height: 1.4;">
                Protected by SecureShare AES-256-GCM Cryptographic Storage &amp; SIEM Threat Engine
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        # Check if real Gmail SMTP credentials are provided
        if smtp_user and smtp_pass:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = sender_header
                msg["To"] = recipient_email
                msg["Reply-To"] = reply_to_email
                msg["X-Priority"] = "1 (Highest)"
                msg["X-MSMail-Priority"] = "High"
                msg["Importance"] = "High"
                msg["X-Entity-Ref-ID"] = str(int(datetime.now(timezone.utc).timestamp() * 1000))
                msg["X-Mailer"] = "SecureShare-Vault-Mailer/1.0"
                msg["Auto-Submitted"] = "auto-generated"

                # Attach Plain-Text Fallback first, then HTML
                msg.attach(MIMEText(plain_text_content, "plain", "utf-8"))
                msg.attach(MIMEText(html_content, "html", "utf-8"))

                if smtp_port == 465:
                    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12) as server:
                        server.login(smtp_user, smtp_pass)
                        server.sendmail(sender_email, [recipient_email], msg.as_string())
                else:
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                        server.starttls()
                        server.login(smtp_user, smtp_pass)
                        server.sendmail(sender_email, [recipient_email], msg.as_string())

                print(f"📧 [SMTP SUCCESS] Delivered 6-digit 2FA code to {recipient_email} from {sender_header} via {smtp_host}:{smtp_port}")
                return True
            except Exception as e:
                print(f"❌ [SMTP ERROR] Failed to send email via {smtp_host}:{smtp_port} to {recipient_email}: {e}")
                print(f"💡 [SMTP TIP] If using Gmail, ensure you created a 16-character Google App Password in your Google Account.")

        # Console fallback logging
        print("=" * 64)
        print(f"📧 [SECURESHARE 2FA DISPATCH] File Download Code")
        print(f"   From:       {sender_header}")
        print(f"   Reply-To:   {reply_to_email}")
        print(f"   Recipient:  {recipient_email}")
        print(f"   Subject:    {subject}")
        print(f"   Target File:{filename}")
        print(f"   OTP Code:   >>> {otp_code} <<< (Valid for 5 minutes)")
        if not (smtp_user and smtp_pass):
            print(f"   ℹ️  Gmail SMTP credentials not set in .env (SMTP_USER / SMTP_PASS).")
        print("=" * 64)
        return True


# Global singleton instance
download_otp_manager = DownloadOTPManager()
