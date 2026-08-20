"""
Access Audit Logger Module
Author: Anuraj
Writes structured JSON audit logs for login attempts into backend/logs/app_access.log.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from .config import LOG_FILE_PATH, LOGS_DIR
except (ImportError, ValueError):
    from config import LOG_FILE_PATH, LOGS_DIR


def log_login_attempt(
    username: str,
    status: str,
    ip: str,
    timestamp: Optional[str] = None,
    status_code: Optional[int] = None,
    endpoint: str = "/api/auth/login",
    method: str = "POST",
    message: Optional[str] = None,
    user_agent: Optional[str] = "-",
    custom_log_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Helper function to record a login attempt into backend/logs/app_access.log.

    Parameters:
    - username: The username or email attempting to authenticate
    - status: 'SUCCESS' or 'FAIL'
    - ip: Client IP address (e.g. '127.0.0.1')
    - timestamp: Optional ISO timestamp. If None, current UTC time is used.
    - status_code: Optional HTTP status code (defaults to 200 for SUCCESS, 401 for FAIL)
    - endpoint: Request endpoint (default: '/api/auth/login')
    - method: HTTP method (default: 'POST')
    - message: Descriptive audit message
    - user_agent: Client user-agent string
    - custom_log_path: Optional custom destination path for testing

    Returns:
    - The structured dictionary written to the log file.
    """
    target_path = Path(custom_log_path) if custom_log_path else Path(LOG_FILE_PATH)

    # Ensure parent directory exists (e.g. backend/logs/)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    normalized_status = "SUCCESS" if str(status).strip().upper() in ("SUCCESS", "200", "OK", "TRUE") else "FAIL"

    if timestamp is None:
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    else:
        ts = timestamp

    if status_code is None:
        status_code = 200 if normalized_status == "SUCCESS" else 401

    if message is None:
        if normalized_status == "SUCCESS":
            message = f"Login successful for user: {username}"
        else:
            message = f"Login failed: Invalid credentials for user: {username}"

    # Structured JSON log payload containing required fields (Timestamp, Username, Status, IP)
    # as well as compatible lowercase fields for backend analyzer/detector interoperability.
    log_entry: Dict[str, Any] = {
        "timestamp": ts,
        "Timestamp": ts,
        "username": username,
        "Username": username,
        "user": username,
        "status": normalized_status,
        "Status": normalized_status,
        "ip": ip,
        "IP": ip,
        "status_code": status_code,
        "endpoint": endpoint,
        "method": method.upper(),
        "message": message,
        "user_agent": user_agent or "-",
    }

    # Write as a single atomic JSON line
    json_line = json.dumps(log_entry) + "\n"
    with open(target_path, "a", encoding="utf-8") as log_file:
        log_file.write(json_line)
        log_file.flush()

    return log_entry
