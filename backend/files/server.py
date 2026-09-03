"""
SecureShare File Sharing Standalone Server
Author: Ahmed / Anfas
Provides a robust multi-threaded HTTP REST API service with CORS support
for AES-256-GCM file encryption, storage, SHA-256 integrity verification,
Two-Factor Email OTP verification, and secure downloads.
Uses standard Python library (zero extra dependencies required).
"""

import os
import sys
import json
import re
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime, timezone
from typing import Any, Optional, Dict, Tuple

try:
    from http.server import ThreadingHTTPServer as BaseHTTPServer
except ImportError:
    from http.server import HTTPServer as BaseHTTPServer

from http.server import BaseHTTPRequestHandler

# Ensure backend package is in python path
_files_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_files_dir)
_root_dir = os.path.dirname(_backend_dir)

for path in [_root_dir, _backend_dir, _files_dir]:
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from backend.files.storage_manager import (
        FileStorageManager,
        StorageError,
        FileNotFoundStorageError,
    )
    from backend.files.crypto import FileEncryptor, DecryptionError, IntegrityVerificationError
    from backend.files.otp_manager import download_otp_manager
except (ImportError, ValueError):
    from storage_manager import (
        FileStorageManager,
        StorageError,
        FileNotFoundStorageError,
    )
    from crypto import FileEncryptor, DecryptionError, IntegrityVerificationError
    from otp_manager import download_otp_manager

# Singleton storage manager instance
storage_manager = FileStorageManager()

LOG_DIR = os.path.join(_backend_dir, "logs")
LOG_FILE = os.environ.get("AUDIT_LOG_FILE", os.path.join(LOG_DIR, "app_access.log"))


def log_file_access(ip: str, method: str, endpoint: str, status_code: int, user: str = "anonymous", message: str = "", user_agent: str = "-"):
    """Appends structured audit log to backend/logs/app_access.log for SIEM detection."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        log_line = (
            f'[{now_str}] IP="{ip}" METHOD="{method}" ENDPOINT="{endpoint}" '
            f'STATUS={status_code} USER="{user}" MSG="{message}" USER_AGENT="{user_agent}"\n'
        )
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"[FileServer] Audit log write error: {e}")


def parse_multipart_form_data(body: bytes, content_type: str) -> Dict[str, Any]:
    """
    Parses multipart/form-data payload from standard browser/axios FormData.
    Returns a dict with 'files' (list of dicts) and 'fields' (dict of field key-values).
    """
    fields: Dict[str, str] = {}
    files: list = []

    match = re.search(r'boundary=([^;]+)', content_type, re.IGNORECASE)
    if not match:
        return {"fields": fields, "files": files}

    boundary = match.group(1).strip('"\'').encode("latin1")
    delimiter = b"--" + boundary

    parts = body.split(delimiter)
    for part in parts:
        part = part.strip()
        if not part or part == b"--":
            continue

        headers_part, _, data_part = part.partition(b"\r\n\r\n")
        if not data_part:
            headers_part, _, data_part = part.partition(b"\n\n")

        headers_str = headers_part.decode("latin1", errors="replace")

        cd_match = re.search(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]+)")?', headers_str, re.IGNORECASE)
        if not cd_match:
            continue

        field_name = cd_match.group(1)
        filename = cd_match.group(2)

        if data_part.endswith(b"\r\n"):
            data_part = data_part[:-2]
        elif data_part.endswith(b"\n"):
            data_part = data_part[:-1]

        if filename:
            ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', headers_str, re.IGNORECASE)
            part_content_type = ct_match.group(1).strip() if ct_match else "application/octet-stream"
            files.append({
                "field": field_name,
                "filename": filename,
                "content_type": part_content_type,
                "data": data_part
            })
        else:
            fields[field_name] = data_part.decode("utf-8", errors="replace")

    return {"fields": fields, "files": files}


class FilesAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Secure File Vault REST endpoints."""

    def _get_client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _get_user_agent(self) -> str:
        return self.headers.get("User-Agent", "curl/8.0.1")

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json", extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, X-SHA256-Checksum, X-Encryption-Standard, X-OTP-Required")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self._set_headers(204, "text/plain")

    def _send_json(self, data: Any, status_code: int = 200):
        """Helper to send structured JSON."""
        self._set_headers(status_code, "application/json")
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.wfile.write(body)

    def _send_error(self, message: str, status_code: int = 400):
        """Helper to send structured JSON error."""
        self._send_json({"error": message, "detail": message, "status": status_code}, status_code=status_code)

    def do_GET(self):
        """Handle GET requests for files, stats, integrity verification, OTP requests, and downloads."""
        ip = self._get_client_ip()
        ua = self._get_user_agent()
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")
            if not path:
                path = "/"

            query_params = parse_qs(parsed_url.query)

            # Check for Path Traversal Probing
            unquoted_path = unquote(self.path)
            traversal_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e", r"/etc/passwd", r"/etc/shadow", r"\.env", r"\.git/config"]
            if any(re.search(pat, unquoted_path, re.IGNORECASE) for pat in traversal_patterns):
                log_file_access(
                    ip=ip,
                    method="GET",
                    endpoint=self.path,
                    status_code=400,
                    user="anonymous",
                    message=f"Blocked directory traversal attempt: {unquoted_path}",
                    user_agent=ua
                )
                self._send_error("Blocked directory traversal attempt", status_code=400)
                return

            # 1. Health & Root Check
            if path in ("/health", "/api/health", "/"):
                self._send_json({
                    "service": "SecureShare Secure File Sharing API",
                    "author": "Ahmed",
                    "status": "healthy",
                    "storage_ok": os.path.exists(storage_manager.storage_dir),
                    "features": {
                        "encryption": "AES-256-GCM (Galois/Counter Mode)",
                        "integrity": "SHA-256 Cryptographic Digest",
                        "2fa_email_otp": "Enabled (5-minute expiration)",
                        "storage_path": storage_manager.storage_dir
                    }
                })
                return

            # 2. File List
            if path in ("/api/files/list", "/files/list"):
                file_list = storage_manager.list_files()
                self._send_json(file_list)
                return

            # 3. Storage Statistics
            if path in ("/api/files/stats", "/files/stats"):
                stats = storage_manager.get_storage_stats()
                self._send_json(stats)
                return

            # 4. Request Download OTP (GET support): /api/files/request-download/<file_id>
            req_otp_match = re.match(r'^/(?:api/)?files/request-download(?:/([^/]+))?$', path)
            if req_otp_match:
                file_id = req_otp_match.group(1) or query_params.get("file_id", [""])[0]
                if not file_id:
                    self._send_error("Missing file_id for download OTP request.", status_code=400)
                    return

                info = storage_manager.get_file_info(file_id)
                if not info:
                    self._send_error(f"File with ID '{file_id}' not found.", status_code=404)
                    return

                recipient_email = query_params.get("email", [""])[0]
                if not recipient_email or "@" not in recipient_email:
                    uploader = info.get("uploaded_by", "")
                    if uploader and "@" in uploader:
                        recipient_email = uploader
                    else:
                        recipient_email = "admin@secureshare.local"

                otp_res = download_otp_manager.generate_otp(
                    file_id=file_id,
                    recipient_email=recipient_email,
                    filename=info.get("filename", "Confidential File")
                )

                log_file_access(
                    ip=ip,
                    method="GET",
                    endpoint=self.path,
                    status_code=200,
                    user=recipient_email,
                    message=f"Generated 5-minute download OTP for file '{info.get('filename')}'",
                    user_agent=ua
                )

                self._send_json({
                    "status": "otp_sent",
                    "message": f"Verification code sent to {otp_res['recipient_email']}",
                    "file_id": file_id,
                    "filename": info.get("filename"),
                    "recipient_email": otp_res["recipient_email"],
                    "expires_in_seconds": otp_res["expires_in_seconds"],
                    "dev_otp": otp_res["dev_otp"]
                })
                return

            # 5. Download File: /api/files/download/<file_id> (with optional ?otp=...)
            download_match = re.match(r'^/(?:api/)?files/download/([^/]+)$', path)
            if download_match:
                file_id = download_match.group(1)
                otp_code = query_params.get("otp", [""])[0]

                # If OTP query param provided, verify it
                if otp_code:
                    is_valid, reason = download_otp_manager.verify_otp(file_id, otp_code)
                    if not is_valid:
                        log_file_access(
                            ip=ip,
                            method="GET",
                            endpoint=self.path,
                            status_code=401,
                            user="anonymous",
                            message=f"Failed file download: Invalid OTP code ({reason})",
                            user_agent=ua
                        )
                        self._send_error(f"Failed file download: Invalid OTP code ({reason})", status_code=401)
                        return

                try:
                    decrypted_bytes, meta = storage_manager.get_file(file_id)
                    filename = meta.get("filename", "downloaded_file")
                    content_type = meta.get("content_type", "application/octet-stream")

                    extra_headers = {
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Content-Length": str(len(decrypted_bytes)),
                        "X-SHA256-Checksum": meta.get("sha256_hash", ""),
                        "X-Encryption-Standard": meta.get("encryption_algorithm", "AES-256-GCM"),
                    }
                    self._set_headers(200, content_type=content_type, extra_headers=extra_headers)
                    self.wfile.write(decrypted_bytes)
                    log_file_access(ip, "GET", self.path, 200, meta.get("uploaded_by", "anonymous"), f"Successful file download: '{filename}' ({len(decrypted_bytes)} bytes)", ua)
                    return
                except FileNotFoundStorageError as fnfe:
                    log_file_access(ip, "GET", self.path, 404, "anonymous", str(fnfe), ua)
                    self._send_error(str(fnfe), status_code=404)
                    return
                except IntegrityVerificationError as ive:
                    log_file_access(ip, "GET", self.path, 422, "anonymous", f"Integrity check failed: {str(ive)}", ua)
                    self._send_error(f"Integrity check failed: {str(ive)}", status_code=422)
                    return
                except DecryptionError as de:
                    log_file_access(ip, "GET", self.path, 422, "anonymous", f"Decryption failed: {str(de)}", ua)
                    self._send_error(f"Decryption authentication failed: {str(de)}", status_code=422)
                    return

            # 6. Verify Integrity: /api/files/verify/<file_id>
            verify_match = re.match(r'^/(?:api/)?files/verify/([^/]+)$', path)
            if verify_match:
                file_id = verify_match.group(1)
                try:
                    result = storage_manager.verify_file_integrity(file_id)
                    self._send_json(result)
                    return
                except FileNotFoundStorageError as fnfe:
                    self._send_error(str(fnfe), status_code=404)
                    return

            # 7. File Metadata Info: /api/files/info/<file_id>
            info_match = re.match(r'^/(?:api/)?files/info/([^/]+)$', path)
            if info_match:
                file_id = info_match.group(1)
                info = storage_manager.get_file_info(file_id)
                if info:
                    self._send_json(info)
                else:
                    self._send_error(f"File with ID '{file_id}' not found.", status_code=404)
                return

            log_file_access(ip, "GET", self.path, 404, "anonymous", f"Endpoint '{path}' not found", ua)
            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            log_file_access(ip, "GET", self.path, 500, "anonymous", f"Internal error: {str(e)}", ua)
            self._send_error(f"Internal server error: {str(e)}", status_code=500)

    def do_POST(self):
        """Handle POST requests (file upload, OTP request, and OTP download verification)."""
        ip = self._get_client_ip()
        ua = self._get_user_agent()
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")

            # 1. Request Download OTP: /api/files/request-download/:file_id or /api/files/request-download
            req_otp_match = re.match(r'^/(?:api/)?files/request-download(?:/([^/]+))?$', path)
            if req_otp_match:
                content_length = int(self.headers.get("Content-Length", 0))
                req_json = {}
                if content_length > 0:
                    try:
                        raw_body = self.rfile.read(content_length)
                        req_json = json.loads(raw_body.decode("utf-8"))
                    except Exception:
                        pass

                file_id = req_otp_match.group(1) or req_json.get("file_id") or ""
                if not file_id:
                    self._send_error("Missing file_id for download OTP request.", status_code=400)
                    return

                info = storage_manager.get_file_info(file_id)
                if not info:
                    self._send_error(f"File with ID '{file_id}' not found.", status_code=404)
                    return

                recipient_email = req_json.get("email") or self.headers.get("X-User-Email") or ""
                if not recipient_email or "@" not in recipient_email:
                    uploader = info.get("uploaded_by", "")
                    if uploader and "@" in uploader:
                        recipient_email = uploader
                    else:
                        recipient_email = "admin@secureshare.local"

                otp_res = download_otp_manager.generate_otp(
                    file_id=file_id,
                    recipient_email=recipient_email,
                    filename=info.get("filename", "Confidential File")
                )

                log_file_access(
                    ip=ip,
                    method="POST",
                    endpoint=self.path,
                    status_code=200,
                    user=recipient_email,
                    message=f"Generated 5-minute download OTP for file '{info.get('filename')}'",
                    user_agent=ua
                )

                self._send_json({
                    "status": "otp_sent",
                    "message": f"Verification code sent to {otp_res['recipient_email']}",
                    "file_id": file_id,
                    "filename": info.get("filename"),
                    "recipient_email": otp_res["recipient_email"],
                    "expires_in_seconds": otp_res["expires_in_seconds"],
                    "dev_otp": otp_res["dev_otp"]
                })
                return

            # 2. Verify Download OTP & Stream File: /api/files/verify-download
            if path in ("/api/files/verify-download", "/files/verify-download"):
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length <= 0:
                    self._send_error("Empty verify-download payload.", status_code=400)
                    return

                try:
                    raw_body = self.rfile.read(content_length)
                    req_json = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    self._send_error("Invalid JSON payload for verify-download.", status_code=400)
                    return

                file_id = req_json.get("file_id", "").strip()
                otp_code = str(req_json.get("otp_code", "")).strip()

                if not file_id or not otp_code:
                    self._send_error("Both file_id and 6-digit otp_code are required.", status_code=400)
                    return

                # Validate OTP
                is_valid, reason = download_otp_manager.verify_otp(file_id=file_id, submitted_code=otp_code)
                if not is_valid:
                    log_file_access(
                        ip=ip,
                        method="POST",
                        endpoint="/api/files/verify-download",
                        status_code=401,
                        user="anonymous",
                        message=f"Failed file download: Invalid OTP code ({reason})",
                        user_agent=ua
                    )
                    self._send_error(f"Failed file download: Invalid OTP code. {reason}", status_code=401)
                    return

                # If OTP is valid, decrypt and stream the file
                try:
                    decrypted_bytes, meta = storage_manager.get_file(file_id)
                    filename = meta.get("filename", "downloaded_file")
                    content_type = meta.get("content_type", "application/octet-stream")

                    extra_headers = {
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Content-Length": str(len(decrypted_bytes)),
                        "X-SHA256-Checksum": meta.get("sha256_hash", ""),
                        "X-Encryption-Standard": meta.get("encryption_algorithm", "AES-256-GCM"),
                    }
                    self._set_headers(200, content_type=content_type, extra_headers=extra_headers)
                    self.wfile.write(decrypted_bytes)

                    log_file_access(
                        ip=ip,
                        method="POST",
                        endpoint="/api/files/verify-download",
                        status_code=200,
                        user=meta.get("uploaded_by", "anonymous"),
                        message=f"Successful file download with verified OTP: '{filename}' ({len(decrypted_bytes)} bytes)",
                        user_agent=ua
                    )
                    return
                except FileNotFoundStorageError as fnfe:
                    log_file_access(ip, "POST", self.path, 404, "anonymous", str(fnfe), ua)
                    self._send_error(str(fnfe), status_code=404)
                    return
                except IntegrityVerificationError as ive:
                    log_file_access(ip, "POST", self.path, 422, "anonymous", f"Integrity check failed: {str(ive)}", ua)
                    self._send_error(f"Integrity check failed: {str(ive)}", status_code=422)
                    return
                except DecryptionError as de:
                    log_file_access(ip, "POST", self.path, 422, "anonymous", f"Decryption failed: {str(de)}", ua)
                    self._send_error(f"Decryption authentication failed: {str(de)}", status_code=422)
                    return

            # 3. File Upload: /api/files/upload
            if path in ("/api/files/upload", "/files/upload"):
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length <= 0:
                    self._send_error("Empty upload request payload.", status_code=400)
                    return

                content_type = self.headers.get("Content-Type", "")
                raw_body = self.rfile.read(content_length)

                file_bytes = b""
                filename = "unnamed_file"
                description = ""
                uploaded_by = "anonymous"

                if "multipart/form-data" in content_type:
                    parsed_form = parse_multipart_form_data(raw_body, content_type)
                    if parsed_form["files"]:
                        first_file = parsed_form["files"][0]
                        filename = first_file["filename"]
                        file_bytes = first_file["data"]
                    description = parsed_form["fields"].get("description", "")
                    uploaded_by = parsed_form["fields"].get("uploaded_by", "anonymous")
                else:
                    file_bytes = raw_body
                    filename = self.headers.get("X-Filename", "encrypted_file.bin")
                    description = self.headers.get("X-Description", "")
                    uploaded_by = self.headers.get("X-User", "anonymous")

                if not file_bytes:
                    self._send_error("No file payload was uploaded.", status_code=400)
                    return

                meta = storage_manager.save_file(
                    file_bytes=file_bytes,
                    filename=filename,
                    description=description,
                    uploaded_by=uploaded_by,
                    content_type="application/octet-stream"
                )

                log_file_access(
                    ip=ip,
                    method="POST",
                    endpoint="/api/files/upload",
                    status_code=201,
                    user=uploaded_by,
                    message=f"Uploaded and encrypted file '{filename}' with AES-256-GCM (SHA-256: {meta.get('sha256_hash')[:16]}...)",
                    user_agent=ua
                )

                self._send_json({
                    "message": f"File '{filename}' successfully encrypted and stored.",
                    "status": "success",
                    "file": meta
                }, status_code=201)
                return

            # POST /api/files/delete/:file_id or /api/files/delete
            del_match = re.match(r'^/(?:api/)?files/delete(?:/([^/]+))?$', path)
            if del_match:
                content_length = int(self.headers.get("Content-Length", 0))
                req_json = {}
                if content_length > 0:
                    try:
                        raw_body = self.rfile.read(content_length)
                        req_json = json.loads(raw_body.decode("utf-8"))
                    except Exception:
                        pass
                file_id = del_match.group(1) or req_json.get("file_id") or ""
                if not file_id:
                    self._send_error("Missing file_id for deletion.", status_code=400)
                    return
                try:
                    storage_manager.delete_file(file_id)
                    log_file_access(ip, "DELETE", self.path, 200, "anonymous", f"Deleted encrypted file ID '{file_id}'", ua)
                    self._send_json({"message": f"File '{file_id}' deleted successfully.", "deleted": True})
                except Exception as e:
                    self._send_error(str(e), status_code=404)
                return

            log_file_access(ip, "POST", self.path, 404, "anonymous", f"Endpoint '{path}' not found", ua)
            self._send_error(f"POST Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            log_file_access(ip, "POST", self.path, 500, "anonymous", f"Internal error: {str(e)}", ua)
            self._send_error(f"File upload error: {str(e)}", status_code=500)

    def do_DELETE(self):
        """Handle DELETE requests to remove encrypted files."""
        ip = self._get_client_ip()
        ua = self._get_user_agent()
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")

            delete_match = re.match(r'^/(?:api/)?files/(?:delete/)?([^/]+)$', path)
            if delete_match:
                file_id = delete_match.group(1).strip()
                try:
                    success = storage_manager.delete_file(file_id)
                    log_file_access(ip, "DELETE", self.path, 200, "anonymous", f"Deleted encrypted file ID '{file_id}'", ua)
                    self._send_json({"message": f"File with ID '{file_id}' deleted successfully.", "deleted": True})
                    return
                except Exception as ex:
                    log_file_access(ip, "DELETE", self.path, 404, "anonymous", f"File ID '{file_id}' error: {ex}", ua)
                    self._send_error(f"File with ID '{file_id}' not found or error: {str(ex)}", status_code=404)
                    return

            log_file_access(ip, "DELETE", self.path, 404, "anonymous", f"Endpoint '{path}' not found", ua)
            self._send_error(f"DELETE Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            log_file_access(ip, "DELETE", self.path, 500, "anonymous", f"Internal error: {str(e)}", ua)
            self._send_error(f"File delete error: {str(e)}", status_code=500)

    def log_message(self, format, *args):
        """Suppress default standard error request spam in console."""
        pass


def run_server(port: int = 8001, host: str = "0.0.0.0"):
    """Starts the standalone File Sharing Storage Server."""
    server_address = (host, port)
    httpd = BaseHTTPServer(server_address, FilesAPIHandler)
    print("=" * 60)
    print(f"🔒 SecureShare File Storage Server listening at http://{host}:{port}")
    print(f"📁 Encrypted Vault Directory: {storage_manager.storage_dir}")
    print("🔑 Encryption Standard: AES-256-GCM (Authenticated Encryption)")
    print("🔐 2FA Email OTP Verification: Active (5-minute expiration)")
    print("=" * 60)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SecureShare Files] Server stopped by operator.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = int(os.environ.get("FILES_PORT", 8001))
    run_server(port=port)
