"""
SecureShare File Sharing Standalone Server
Author: Ahmed / Anfas
Provides a robust multi-threaded HTTP REST API service with CORS support
for AES-256-GCM file encryption, storage, SHA-256 integrity verification, and download.
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
except (ImportError, ValueError):
    from storage_manager import (
        FileStorageManager,
        StorageError,
        FileNotFoundStorageError,
    )
    from crypto import FileEncryptor, DecryptionError, IntegrityVerificationError

# Singleton storage manager instance
storage_manager = FileStorageManager()


def parse_multipart_form_data(body: bytes, content_type: str) -> Dict[str, Any]:
    """
    Parses multipart/form-data payload from standard browser/axios FormData.
    Returns a dict with 'files' (list of dicts) and 'fields' (dict of field key-values).
    """
    fields: Dict[str, str] = {}
    files: list = []

    # Extract boundary
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

        if b"\r\n\r\n" in part:
            header_data, content = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            header_data, content = part.split(b"\n\n", 1)
        else:
            continue

        # Strip trailing \r\n if present
        if content.endswith(b"\r\n"):
            content = content[:-2]
        elif content.endswith(b"\n"):
            content = content[:-1]

        header_text = header_data.decode("latin1", errors="replace")

        # Parse Content-Disposition
        cd_match = re.search(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"(?:;\s*filename="([^"]+)")?', header_text, re.IGNORECASE)
        if not cd_match:
            continue

        field_name = cd_match.group(1)
        filename = cd_match.group(2)

        # Parse Content-Type if file
        ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', header_text, re.IGNORECASE)
        part_content_type = ct_match.group(1).strip() if ct_match else "application/octet-stream"

        if filename is not None:
            files.append({
                "field_name": field_name,
                "filename": filename,
                "content_type": part_content_type,
                "data": content
            })
        else:
            fields[field_name] = content.decode("utf-8", errors="replace")

    return {"fields": fields, "files": files}


class FilesAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Secure File Vault REST endpoints."""

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json", extra_headers: Optional[Dict[str, str]] = None):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, X-SHA256-Checksum, X-Encryption-Standard")
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
        """Handle GET requests for files, stats, integrity verification, and downloads."""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")
            if not path:
                path = "/"

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

            # 4. Download File: /api/files/download/<file_id>
            download_match = re.match(r'^/(?:api/)?files/download/([^/]+)$', path)
            if download_match:
                file_id = download_match.group(1)
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
                    return
                except FileNotFoundStorageError as fnfe:
                    self._send_error(str(fnfe), status_code=404)
                    return
                except IntegrityVerificationError as ive:
                    self._send_error(f"Integrity check failed: {str(ive)}", status_code=422)
                    return
                except DecryptionError as de:
                    self._send_error(f"Decryption authentication failed: {str(de)}", status_code=422)
                    return

            # 5. Verify Integrity: /api/files/verify/<file_id>
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

            # 6. File Metadata Info: /api/files/info/<file_id>
            info_match = re.match(r'^/(?:api/)?files/info/([^/]+)$', path)
            if info_match:
                file_id = info_match.group(1)
                info = storage_manager.get_file_info(file_id)
                if info:
                    self._send_json(info)
                else:
                    self._send_error(f"File with ID '{file_id}' not found.", status_code=404)
                return

            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            self._send_error(f"Internal server error: {str(e)}", status_code=500)

    def do_POST(self):
        """Handle POST requests (file upload)."""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")

            if path in ("/api/files/upload", "/files/upload"):
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length <= 0:
                    self._send_error("Empty upload request payload.", status_code=400)
                    return

                content_type = self.headers.get("Content-Type", "")
                raw_body = self.rfile.read(content_length)

                file_bytes = b""
                filename = "unnamed_file"
                file_ct = "application/octet-stream"
                description = ""

                if "multipart/form-data" in content_type:
                    parsed_form = parse_multipart_form_data(raw_body, content_type)
                    description = parsed_form["fields"].get("description", "")
                    if not parsed_form["files"]:
                        self._send_error("No file provided in form data under 'file' key.", status_code=400)
                        return
                    uploaded_file = parsed_form["files"][0]
                    file_bytes = uploaded_file["data"]
                    filename = uploaded_file["filename"]
                    file_ct = uploaded_file["content_type"]
                elif "application/json" in content_type:
                    try:
                        data = json.loads(raw_body.decode("utf-8"))
                        filename = data.get("filename", "document.txt")
                        description = data.get("description", "")
                        content_str = data.get("content", "")
                        file_bytes = content_str.encode("utf-8")
                    except Exception:
                        self._send_error("Invalid JSON body", status_code=400)
                        return
                else:
                    file_bytes = raw_body
                    filename = "uploaded_payload.bin"

                if not file_bytes:
                    self._send_error("Cannot upload empty file.", status_code=400)
                    return

                # Encrypt and save
                meta = storage_manager.save_file(
                    file_content=file_bytes,
                    original_filename=filename,
                    content_type=file_ct,
                    description=description
                )

                self._send_json(meta, status_code=201)
                return

            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            self._send_error(f"File upload processing failed: {str(e)}", status_code=500)

    def do_DELETE(self):
        """Handle DELETE requests (secure file deletion)."""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")

            delete_match = re.match(r'^/(?:api/)?files/([^/]+)$', path)
            if delete_match:
                file_id = delete_match.group(1)
                try:
                    storage_manager.delete_file(file_id)
                    self._send_json({
                        "status": "success",
                        "message": f"File '{file_id}' deleted securely from vault.",
                        "file_id": file_id
                    })
                    return
                except FileNotFoundStorageError as fnfe:
                    self._send_error(str(fnfe), status_code=404)
                    return

            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            self._send_error(f"Delete operation failed: {str(e)}", status_code=500)

    def log_message(self, format_str, *args):
        """Suppress stdout noise."""
        return


DEFAULT_FILES_PORT = int(os.environ.get("FILES_PORT", os.environ.get("PORT", "8001")))


class FileServer:
    """Multi-threaded REST API server for Encrypted File Sharing Vault."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_FILES_PORT):
        self.host = host
        self.port = port
        self.httpd = BaseHTTPServer((self.host, self.port), FilesAPIHandler)

    def start(self):
        """Start the HTTP server (blocking)."""
        print(f"[SecureShare File Vault] Server started at http://{self.host}:{self.port}")
        print(f"[SecureShare File Vault] Storage path: {storage_manager.storage_dir}")
        print("[SecureShare File Vault] AES-256-GCM Authenticated Encryption active.")
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SecureShare File Vault] Shutting down server gracefully...")
        finally:
            self.httpd.server_close()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_server(host: str = "0.0.0.0", port: int = DEFAULT_FILES_PORT):
    server = FileServer(host=host, port=port)
    server.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureShare Encrypted File Vault API Server")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_FILES_PORT, help=f"Port to listen on (default: {DEFAULT_FILES_PORT})")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)
