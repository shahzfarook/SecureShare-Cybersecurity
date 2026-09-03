"""
Threat Detection Engine for SecureShare Cybersecurity
Author: Anfas
Role: Real-time & batch analysis of access logs for brute-force attacks,
credential stuffing, path traversal, injection probing, and rate anomalies.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import hashlib
import re
import os
import sys
from urllib.parse import unquote

_analyzer_dir = os.path.dirname(os.path.abspath(__file__))
if _analyzer_dir not in sys.path:
    sys.path.insert(0, _analyzer_dir)

try:
    from .parser import LogEntry, LogParser  # type: ignore[missing-import] # pyrefly: ignore
except (ImportError, ValueError):
    from parser import LogEntry, LogParser  # type: ignore[missing-import] # pyrefly: ignore


@dataclass
class SecurityAlert:
    id: str
    alert_type: str              # 'BRUTE_FORCE_ATTACK', 'CREDENTIAL_STUFFING', 'PATH_TRAVERSAL', etc.
    severity: str                # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    ip: str
    target_user: str
    count: int
    time_window_seconds: int
    first_seen: datetime
    last_seen: datetime
    message: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_advice: str = ""
    resolved: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "ip": self.ip,
            "target_user": self.target_user,
            "count": self.count,
            "time_window_seconds": self.time_window_seconds,
            "first_seen": self.first_seen.isoformat() if isinstance(self.first_seen, datetime) else str(self.first_seen),
            "last_seen": self.last_seen.isoformat() if isinstance(self.last_seen, datetime) else str(self.last_seen),
            "message": self.message,
            "evidence": self.evidence,
            "mitigation_advice": self.mitigation_advice,
            "resolved": self.resolved,
            "created_at": self.created_at.isoformat() if isinstance(self.created_at, datetime) else str(self.created_at)
        }


class LogAnalyzer:
    """
    Log Analyzer detection engine.
    Applies sliding-window algorithms and threat signatures against parsed LogEntry objects.
    """

    # Detection Thresholds
    BRUTE_FORCE_THRESHOLD = 5         # > 5 failed attempts
    BRUTE_FORCE_WINDOW = 60           # in 60 seconds
    CRED_STUFFING_USER_THRESHOLD = 3  # > 3 distinct users from single IP
    CRED_STUFFING_WINDOW = 120        # in 120 seconds
    RATE_ANOMALY_THRESHOLD = 30       # > 30 requests in 10s
    RATE_ANOMALY_WINDOW = 10
    UNAUTH_SPIKE_THRESHOLD = 4        # > 4 403 Forbidden in 60s
    UNAUTH_SPIKE_WINDOW = 60

    # Threat Signatures
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./|\.\.\\|\.%2e/|\.%2e%2e|%2e%2e/|%252e%252e", re.IGNORECASE),
        re.compile(r"/etc/(?:passwd|shadow|hosts|group)", re.IGNORECASE),
        re.compile(r"(?:\.env|\.git|\.aws|\.ssh|wp-config|web\.config|id_rsa)", re.IGNORECASE),
        re.compile(r"/proc/self/(?:environ|cmdline|fd)", re.IGNORECASE),
    ]

    SQLI_PATTERNS = [
        re.compile(r"(?:\'|\%27)\s*(?:or|and)\s*[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.IGNORECASE),
        re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
        re.compile(r"exec(?:\s|\+)+(?:xp_cmdshell|sp_executesql)", re.IGNORECASE),
        re.compile(r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.IGNORECASE),
        re.compile(r"--\s*$|/\*.*?\*/", re.IGNORECASE),
    ]

    XSS_PATTERNS = [
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript:\s*", re.IGNORECASE),
        re.compile(r"(?:onerror|onload|onclick|onmouseover)\s*=", re.IGNORECASE),
        re.compile(r"<svg/onload=", re.IGNORECASE),
    ]

    def __init__(self, parser: Optional[LogParser] = None):
        self.parser = parser or LogParser()

    @staticmethod
    def _generate_alert_id(alert_type: str, ip: str, timestamp: datetime) -> str:
        """Create a deterministic unique alert ID."""
        ts_key = int(timestamp.timestamp())
        raw_key = f"{alert_type}:{ip}:{ts_key}"
        hash_suffix = hashlib.md5(raw_key.encode()).hexdigest()[:8]
        return f"ALERT-{alert_type[:12]}-{ip.replace(':', '_')}-{hash_suffix}".upper()

    def detect_brute_force(self, entries: List[LogEntry]) -> List[SecurityAlert]:
        """
        Flag BRUTE_FORCE_ATTACK if an IP has >5 failed login attempts within 60 seconds.
        Uses a sliding-window algorithm per IP.
        """
        alerts: List[SecurityAlert] = []
        ip_failed_logins: Dict[str, List[LogEntry]] = {}
        for entry in entries:
            if entry.is_failed_login():
                ip_failed_logins.setdefault(entry.ip, []).append(entry)

        for ip, failed_list in ip_failed_logins.items():
            failed_list.sort(key=lambda x: x.timestamp)
            n = len(failed_list)
            if n <= self.BRUTE_FORCE_THRESHOLD:
                continue

            i = 0
            while i < n:
                window_entries = [failed_list[i]]
                start_time = failed_list[i].timestamp
                j = i + 1
                while j < n and (failed_list[j].timestamp - start_time).total_seconds() <= self.BRUTE_FORCE_WINDOW:
                    window_entries.append(failed_list[j])
                    j += 1

                if len(window_entries) > self.BRUTE_FORCE_THRESHOLD:
                    users_targeted = list({e.user for e in window_entries if e.user != "anonymous"})
                    primary_user = users_targeted[0] if users_targeted else "multiple/unknown"
                    alert_id = self._generate_alert_id("BRUTE_FORCE_ATTACK", ip, start_time)

                    alert = SecurityAlert(
                        id=alert_id,
                        alert_type="BRUTE_FORCE_ATTACK",
                        severity="CRITICAL" if len(window_entries) >= 10 else "HIGH",
                        ip=ip,
                        target_user=primary_user,
                        count=len(window_entries),
                        time_window_seconds=int((window_entries[-1].timestamp - start_time).total_seconds()) or 1,
                        first_seen=start_time,
                        last_seen=window_entries[-1].timestamp,
                        message=(
                            f"Brute-force attack detected from IP {ip}. "
                            f"{len(window_entries)} failed login attempts within "
                            f"{int((window_entries[-1].timestamp - start_time).total_seconds())} seconds (Target: {primary_user})."
                        ),
                        evidence=[e.to_dict() for e in window_entries[:10]],
                        mitigation_advice=f"Immediately block IP {ip} at the firewall and enforce temporary account lock for user '{primary_user}'."
                    )
                    alerts.append(alert)
                    i = j
                else:
                    i += 1

        return alerts

    def detect_credential_stuffing(self, entries: List[LogEntry]) -> List[SecurityAlert]:
        """
        Flag CREDENTIAL_STUFFING if single IP attempts failed logins across > 3 distinct usernames
        within a 120-second sliding window.
        """
        alerts: List[SecurityAlert] = []
        ip_failed_logins: Dict[str, List[LogEntry]] = {}
        for entry in entries:
            if entry.is_failed_login() and entry.user not in ("", "anonymous", "unknown", "-"):
                target_str = f"{entry.user} {entry.raw}"
                is_sqli = any(pat.search(target_str) for pat in self.SQLI_PATTERNS)
                if not is_sqli:
                    ip_failed_logins.setdefault(entry.ip, []).append(entry)

        for ip, failed_list in ip_failed_logins.items():
            failed_list.sort(key=lambda x: x.timestamp)
            n = len(failed_list)
            if n <= self.CRED_STUFFING_USER_THRESHOLD:
                continue

            i = 0
            while i < n:
                start_time = failed_list[i].timestamp
                window_entries = [failed_list[i]]
                j = i + 1
                while j < n and (failed_list[j].timestamp - start_time).total_seconds() <= self.CRED_STUFFING_WINDOW:
                    window_entries.append(failed_list[j])
                    j += 1

                unique_users = {e.user for e in window_entries}
                if len(unique_users) > self.CRED_STUFFING_USER_THRESHOLD:
                    alert_id = self._generate_alert_id("CREDENTIAL_STUFFING", ip, start_time)
                    alert = SecurityAlert(
                        id=alert_id,
                        alert_type="CREDENTIAL_STUFFING",
                        severity="HIGH",
                        ip=ip,
                        target_user=f"{len(unique_users)} users: " + ", ".join(list(unique_users)[:4]),
                        count=len(window_entries),
                        time_window_seconds=int((window_entries[-1].timestamp - start_time).total_seconds()) or 1,
                        first_seen=start_time,
                        last_seen=window_entries[-1].timestamp,
                        message=(
                            f"Credential stuffing detected from IP {ip}. "
                            f"{len(window_entries)} login attempts across {len(unique_users)} distinct usernames."
                        ),
                        evidence=[e.to_dict() for e in window_entries[:10]],
                        mitigation_advice="Enable CAPTCHA on /auth/login and place rate-limiting on authentication endpoints."
                    )
                    alerts.append(alert)
                    i = j
                else:
                    i += 1

        return alerts

    def detect_web_attack_probing(self, entries: List[LogEntry]) -> List[SecurityAlert]:
        """
        Flag PATH_TRAVERSAL, SQL_INJECTION, and XSS_PROBING attacks based on payload signatures.
        """
        alerts: List[SecurityAlert] = []
        suspicious_by_type_ip: Dict[str, List[LogEntry]] = {}

        for entry in entries:
            target_str = f"{entry.endpoint} {entry.message} {entry.raw}"
            unquoted_target = unquote(target_str)
            check_targets = [target_str, unquoted_target]

            # Path Traversal
            traversal_matched = False
            for pat in self.PATH_TRAVERSAL_PATTERNS:
                if any(pat.search(t) for t in check_targets):
                    key = f"PATH_TRAVERSAL:{entry.ip}"
                    suspicious_by_type_ip.setdefault(key, []).append(entry)
                    traversal_matched = True
                    break

            if traversal_matched:
                continue

            # SQL Injection
            sqli_matched = False
            for pat in self.SQLI_PATTERNS:
                if any(pat.search(t) for t in check_targets):
                    key = f"SQL_INJECTION:{entry.ip}"
                    suspicious_by_type_ip.setdefault(key, []).append(entry)
                    sqli_matched = True
                    break

            if sqli_matched:
                continue

            # XSS Probing
            for pat in self.XSS_PATTERNS:
                if any(pat.search(t) for t in check_targets):
                    key = f"XSS_PROBING:{entry.ip}"
                    suspicious_by_type_ip.setdefault(key, []).append(entry)
                    break

        for key, matching_entries in suspicious_by_type_ip.items():
            alert_type, ip = key.split(":", 1)
            matching_entries.sort(key=lambda x: x.timestamp)
            first_seen = matching_entries[0].timestamp
            last_seen = matching_entries[-1].timestamp
            alert_id = self._generate_alert_id(alert_type, ip, first_seen)

            severity = "CRITICAL" if alert_type == "SQL_INJECTION" else "HIGH"
            alert = SecurityAlert(
                id=alert_id,
                alert_type=alert_type,
                severity=severity,
                ip=ip,
                target_user=matching_entries[0].user or "system",
                count=len(matching_entries),
                time_window_seconds=int((last_seen - first_seen).total_seconds()) or 1,
                first_seen=first_seen,
                last_seen=last_seen,
                message=f"Malicious {alert_type.replace('_', ' ')} probe detected from IP {ip} ({len(matching_entries)} requests).",
                evidence=[e.to_dict() for e in matching_entries[:10]],
                mitigation_advice="Inspect web application firewall (WAF) rules and sanitize input parameters on target endpoints."
            )
            alerts.append(alert)

        return alerts

    def detect_rate_anomalies(self, entries: List[LogEntry]) -> List[SecurityAlert]:
        """
        Flag RATE_ANOMALY / DDoS burst if an IP sends > 30 requests in 10 seconds.
        """
        alerts: List[SecurityAlert] = []
        ip_entries: Dict[str, List[LogEntry]] = {}
        for entry in entries:
            ip_entries.setdefault(entry.ip, []).append(entry)

        for ip, req_list in ip_entries.items():
            req_list.sort(key=lambda x: x.timestamp)
            n = len(req_list)
            if n <= self.RATE_ANOMALY_THRESHOLD:
                continue

            i = 0
            while i < n:
                start_time = req_list[i].timestamp
                window_entries = [req_list[i]]
                j = i + 1
                while j < n and (req_list[j].timestamp - start_time).total_seconds() <= self.RATE_ANOMALY_WINDOW:
                    window_entries.append(req_list[j])
                    j += 1

                if len(window_entries) > self.RATE_ANOMALY_THRESHOLD:
                    alert_id = self._generate_alert_id("RATE_ANOMALY", ip, start_time)
                    alert = SecurityAlert(
                        id=alert_id,
                        alert_type="RATE_ANOMALY",
                        severity="HIGH" if any(e.status_code >= 400 for e in window_entries) else "MEDIUM",
                        ip=ip,
                        target_user="system",
                        count=len(window_entries),
                        time_window_seconds=int((window_entries[-1].timestamp - start_time).total_seconds()) or 1,
                        first_seen=start_time,
                        last_seen=window_entries[-1].timestamp,
                        message=f"High-frequency request burst detected from IP {ip}: {len(window_entries)} requests within {self.RATE_ANOMALY_WINDOW} seconds.",
                        evidence=[e.to_dict() for e in window_entries[:10]],
                        mitigation_advice=f"Apply IP-level rate limiting or Cloudflare DDoS protection rules for {ip}."
                    )
                    alerts.append(alert)
                    i = j
                else:
                    i += 1

        return alerts

    def detect_unauthorized_access_spikes(self, entries: List[LogEntry]) -> List[SecurityAlert]:
        """
        Flag UNAUTHORIZED_ACCESS_SPIKE if an IP encounters multiple 403 Forbidden errors
        trying to access protected file directories or administrative endpoints.
        """
        alerts: List[SecurityAlert] = []
        ip_forbidden: Dict[str, List[LogEntry]] = {}
        for entry in entries:
            if entry.status_code == 403:
                ip_forbidden.setdefault(entry.ip, []).append(entry)

        for ip, f_list in ip_forbidden.items():
            f_list.sort(key=lambda x: x.timestamp)
            n = len(f_list)
            if n <= self.UNAUTH_SPIKE_THRESHOLD:
                continue

            i = 0
            while i < n:
                start_time = f_list[i].timestamp
                window_entries = [f_list[i]]
                j = i + 1
                while j < n and (f_list[j].timestamp - start_time).total_seconds() <= self.UNAUTH_SPIKE_WINDOW:
                    window_entries.append(f_list[j])
                    j += 1

                if len(window_entries) > self.UNAUTH_SPIKE_THRESHOLD:
                    alert_id = self._generate_alert_id("UNAUTHORIZED_ACCESS_SPIKE", ip, start_time)
                    alert = SecurityAlert(
                        id=alert_id,
                        alert_type="UNAUTHORIZED_ACCESS_SPIKE",
                        severity="MEDIUM",
                        ip=ip,
                        target_user=window_entries[0].user or "anonymous",
                        count=len(window_entries),
                        time_window_seconds=int((window_entries[-1].timestamp - start_time).total_seconds()) or 1,
                        first_seen=start_time,
                        last_seen=window_entries[-1].timestamp,
                        message=f"Unauthorized access surge (403 Forbidden) from IP {ip}: {len(window_entries)} rejected requests in {self.UNAUTH_SPIKE_WINDOW}s.",
                        evidence=[e.to_dict() for e in window_entries[:10]],
                        mitigation_advice=f"Review file access permission policies and monitor IP {ip} for privilege escalation attempts."
                    )
                    alerts.append(alert)
                    i = j
                else:
                    i += 1

        return alerts

    def analyze(self, entries: Optional[List[LogEntry]] = None) -> List[SecurityAlert]:
        """
        Run full threat detection suite on provided entries (or parses default log file).
        Returns list of SecurityAlert objects sorted by timestamp (newest first).
        """
        if entries is None:
            entries = self.parser.parse_file()

        all_alerts: List[SecurityAlert] = []
        all_alerts.extend(self.detect_brute_force(entries))
        all_alerts.extend(self.detect_credential_stuffing(entries))
        all_alerts.extend(self.detect_web_attack_probing(entries))
        all_alerts.extend(self.detect_rate_anomalies(entries))
        all_alerts.extend(self.detect_unauthorized_access_spikes(entries))

        # Sort newest first
        all_alerts.sort(key=lambda a: a.last_seen, reverse=True)
        return all_alerts

    def get_statistics(
        self,
        entries: Optional[List[LogEntry]] = None,
        alerts: Optional[List[SecurityAlert]] = None
    ) -> Dict[str, Any]:
        """
        Compute aggregate cybersecurity metrics, threat distributions, and timeline for frontend dashboard.
        """
        if entries is None:
            entries = self.parser.parse_file()
        if alerts is None:
            alerts = self.analyze(entries)

        total_requests = len(entries)
        failed_logins = sum(1 for e in entries if e.is_failed_login())
        successful_logins = sum(1 for e in entries if e.is_successful_login())
        unique_ips = len({e.ip for e in entries})
        flagged_ips = len({a.ip for a in alerts})

        critical_alerts = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_alerts = sum(1 for a in alerts if a.severity == "HIGH")
        medium_alerts = sum(1 for a in alerts if a.severity == "MEDIUM")
        low_alerts = sum(1 for a in alerts if a.severity == "LOW")

        threat_breakdown: Dict[str, int] = {}
        for a in alerts:
            threat_breakdown[a.alert_type] = threat_breakdown.get(a.alert_type, 0) + 1

        penalty = (critical_alerts * 25) + (high_alerts * 15) + (medium_alerts * 5) + (low_alerts * 2)
        security_score = max(0, min(100, 100 - penalty))

        if critical_alerts > 0 or high_alerts >= 2:
            system_status = "UNDER_ATTACK"
        elif high_alerts > 0 or medium_alerts >= 2:
            system_status = "ELEVATED_RISK"
        elif medium_alerts > 0 or low_alerts > 0:
            system_status = "WARNING"
        else:
            system_status = "SECURE"

        ip_stats: Dict[str, Dict[str, Any]] = {}
        for e in entries:
            if e.ip not in ip_stats:
                ip_stats[e.ip] = {"ip": e.ip, "request_count": 0, "failed_logins": 0, "alert_count": 0, "alerts": []}
            ip_stats[e.ip]["request_count"] += 1
            if e.is_failed_login():
                ip_stats[e.ip]["failed_logins"] += 1

        for a in alerts:
            if a.ip in ip_stats:
                ip_stats[a.ip]["alert_count"] += 1
                ip_stats[a.ip]["alerts"].append(a.alert_type)

        top_offending_ips = sorted(
            [v for v in ip_stats.values() if v["alert_count"] > 0 or v["failed_logins"] > 0],
            key=lambda x: (x["alert_count"], x["failed_logins"], x["request_count"]),
            reverse=True
        )[:10]

        endpoint_counts: Dict[str, Dict[str, Any]] = {}
        for e in entries:
            if e.endpoint not in endpoint_counts:
                endpoint_counts[e.endpoint] = {"endpoint": e.endpoint, "total": 0, "errors": 0}
            endpoint_counts[e.endpoint]["total"] += 1
            if e.status_code >= 400:
                endpoint_counts[e.endpoint]["errors"] += 1

        top_endpoints = sorted(endpoint_counts.values(), key=lambda x: x["total"], reverse=True)[:10]

        timeline_buckets: Dict[str, Dict[str, Any]] = {}
        for e in entries:
            minute_bucket = e.timestamp.strftime("%Y-%m-%dT%H:%M:00Z")
            if minute_bucket not in timeline_buckets:
                timeline_buckets[minute_bucket] = {
                    "timestamp": minute_bucket,
                    "requests": 0,
                    "failed_logins": 0,
                    "errors": 0
                }
            timeline_buckets[minute_bucket]["requests"] += 1
            if e.is_failed_login():
                timeline_buckets[minute_bucket]["failed_logins"] += 1
            if e.status_code >= 400:
                timeline_buckets[minute_bucket]["errors"] += 1

        timeline = sorted(timeline_buckets.values(), key=lambda x: x["timestamp"])[-30:]

        return {
            "summary": {
                "total_requests": total_requests,
                "total_requests_analyzed": total_requests,
                "total_failed_logins": failed_logins,
                "total_successful_logins": successful_logins,
                "total_threat_alerts": len(alerts),
                "total_alerts": len(alerts),
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "low_alerts": low_alerts,
                "unique_ips": unique_ips,
                "flagged_ips": flagged_ips,
                "security_score": security_score,
                "system_status": system_status,
            },
            "threat_breakdown": threat_breakdown,
            "top_offending_ips": top_offending_ips,
            "top_endpoints": top_endpoints,
            "timeline": timeline,
            "recent_alerts": [a.to_dict() for a in alerts[:5]],
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }
