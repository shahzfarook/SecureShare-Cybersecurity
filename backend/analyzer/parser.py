"""
Log Parser Module for SecureShare Cybersecurity
Author: Anfas
Parses access log entries from backend/logs/app_access.log supporting
both standard key-value tagged formats and structured JSON logs.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
from typing import List, Optional, Dict, Any, Iterable


@dataclass
class LogEntry:
    timestamp: datetime
    ip: str
    method: str
    endpoint: str
    status_code: int
    user: str
    message: str
    user_agent: str
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to JSON-serializable dictionary."""
        return {
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp),
            "ip": self.ip,
            "method": self.method,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "user": self.user,
            "message": self.message,
            "user_agent": self.user_agent,
            "raw": self.raw
        }

    def is_failed_login(self) -> bool:
        """Check if log entry represents a failed login attempt."""
        endpoint_lower = self.endpoint.lower()
        msg_lower = self.message.lower()
        is_auth_endpoint = any(ep in endpoint_lower for ep in [
            "/auth/login", "/api/auth/login", "/login", "/api/login", "/auth", "/token", "/authenticate"
        ])
        is_failed_status = self.status_code in (400, 401, 403, 422)
        has_failed_msg = any(kw in msg_lower for kw in [
            "failed", "invalid credentials", "invalid password", "unauthorized", "bad credentials",
            "authentication failure", "incorrect password", "user not found", "wrong password"
        ])
        if "login failed" in msg_lower or "authentication failed" in msg_lower:
            return True
        if is_auth_endpoint and is_failed_status and (self.status_code == 401 or has_failed_msg):
            return True
        if is_failed_status and has_failed_msg:
            return True
        return False

    def is_successful_login(self) -> bool:
        """Check if log entry represents a successful login."""
        endpoint_lower = self.endpoint.lower()
        msg_lower = self.message.lower()
        is_auth_endpoint = any(ep in endpoint_lower for ep in [
            "/auth/login", "/api/auth/login", "/login", "/api/login"
        ])
        return (is_auth_endpoint and self.status_code == 200) or ("login successful" in msg_lower)


class LogParser:
    """
    Parser for SecureShare access logs.
    Supports formats:
      1. Tagged KV format: [2026-08-17T10:30:15Z] IP="1.2.3.4" METHOD="POST" ENDPOINT="/api/auth/login" STATUS=401 USER="admin" MSG="Login failed" USER_AGENT="..."
      2. JSON format: {"timestamp": "2026-08-17T10:30:15Z", "ip": "1.2.3.4", ...}
    """

    # Regex for standard bracket timestamp + key="value" pairs
    TIMESTAMP_BRACKET_REGEX = re.compile(r"^\[(?P<timestamp>[^\]]+)\]\s*(?P<rest>.*)$")
    KV_PAIR_REGEX = re.compile(r'(\w+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s]+))')

    def __init__(self, default_log_path: Optional[str] = None):
        if default_log_path:
            self.default_log_path = default_log_path
        else:
            self.default_log_path = self._resolve_default_log_path()

    @staticmethod
    def _resolve_default_log_path() -> str:
        """Dynamically resolve backend/logs/app_access.log based on module hierarchy."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
        return os.path.join(backend_dir, "logs", "app_access.log")

    @classmethod
    def _parse_timestamp(cls, ts_str: str) -> datetime:
        """Parse various ISO and common timestamp formats into a UTC-aware datetime object."""
        ts_str = ts_str.strip()
        if not ts_str:
            return datetime.now(timezone.utc)

        # Replace Z with +00:00 for fromisoformat
        if ts_str.endswith("Z"):
            clean_ts = ts_str[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(clean_ts)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y/%m/%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        # Fallback to current UTC time if unparseable
        return datetime.now(timezone.utc)

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line into a LogEntry dataclass.
        Returns None if the line is empty or completely unparseable.
        """
        raw_line = line.strip()
        if not raw_line or raw_line.startswith("#"):
            return None

        # 1. Try parsing as JSON
        if raw_line.startswith("{") and raw_line.endswith("}"):
            try:
                data = json.loads(raw_line)
                ts = self._parse_timestamp(str(data.get("timestamp", "")))
                return LogEntry(
                    timestamp=ts,
                    ip=str(data.get("ip", "unknown")),
                    method=str(data.get("method", "GET")).upper(),
                    endpoint=str(data.get("endpoint", "/")),
                    status_code=int(data.get("status_code", data.get("status", 200))),
                    user=str(data.get("user", data.get("username", "anonymous"))),
                    message=str(data.get("message", data.get("msg", ""))),
                    user_agent=str(data.get("user_agent", data.get("ua", "-"))),
                    raw=raw_line
                )
            except Exception:
                pass

        # 2. Try parsing standard bracket format: [TIMESTAMP] IP="..." METHOD="..." ...
        match = self.TIMESTAMP_BRACKET_REGEX.match(raw_line)
        if match:
            ts_part = match.group("timestamp")
            rest_part = match.group("rest")
            ts = self._parse_timestamp(ts_part)

            pairs: Dict[str, str] = {}
            for k, quoted_v, unquoted_v in self.KV_PAIR_REGEX.findall(rest_part):
                val = (quoted_v if quoted_v != "" else unquoted_v).replace('\\"', '"').replace('\\\\', '\\')
                pairs[k.upper()] = val

            ip = pairs.get("IP", "unknown")
            method = pairs.get("METHOD", "GET").upper()
            endpoint = pairs.get("ENDPOINT", "/")
            try:
                status_code = int(pairs.get("STATUS", pairs.get("STATUS_CODE", "200")))
            except ValueError:
                status_code = 200
            user = pairs.get("USER", pairs.get("USERNAME", "anonymous"))
            message = pairs.get("MSG", pairs.get("MESSAGE", ""))
            user_agent = pairs.get("USER_AGENT", pairs.get("UA", "-"))

            return LogEntry(
                timestamp=ts,
                ip=ip,
                method=method,
                endpoint=endpoint,
                status_code=status_code,
                user=user,
                message=message,
                user_agent=user_agent,
                raw=raw_line
            )

        # 3. Fallback: Split by space
        parts = raw_line.split()
        if len(parts) >= 3:
            return LogEntry(
                timestamp=datetime.now(timezone.utc),
                ip=parts[0] if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[0]) else "unknown",
                method="GET",
                endpoint=parts[1] if parts[1].startswith("/") else "/",
                status_code=200,
                user="anonymous",
                message=raw_line,
                user_agent="-",
                raw=raw_line
            )

        return None

    def parse_lines(self, lines: Iterable[str]) -> List[LogEntry]:
        """Parse multiple log lines and return sorted list of valid LogEntry items."""
        entries: List[LogEntry] = []
        for line in lines:
            entry = self.parse_line(line)
            if entry is not None:
                entries.append(entry)
        entries.sort(key=lambda e: e.timestamp)
        return entries

    def parse_file(self, filepath: Optional[str] = None) -> List[LogEntry]:
        """
        Read and parse log entries from the specified log file.
        If file does not exist, returns an empty list.
        """
        target_path = filepath or self.default_log_path
        if not os.path.exists(target_path):
            return []

        try:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                return self.parse_lines(f)
        except Exception as e:
            print(f"[LogParser] Warning: Could not read log file {target_path}: {e}")
            return []
