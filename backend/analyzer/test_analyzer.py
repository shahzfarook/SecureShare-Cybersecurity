"""
Unit and Integration Test Suite for SecureShare Cybersecurity Log Analyzer
Author: Anfas
Run with: python3 backend/analyzer/test_analyzer.py
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen
from datetime import datetime, timedelta, timezone

# Ensure project root is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

_project_root = os.path.abspath(os.path.join(_current_dir, "..", ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from backend.analyzer.parser import LogParser, LogEntry  # type: ignore[missing-import] # pyrefly: ignore
    from backend.analyzer.detector import LogAnalyzer  # type: ignore[missing-import] # pyrefly: ignore
    from backend.analyzer.server import LogAnalyzerServer  # type: ignore[missing-import] # pyrefly: ignore
    from backend.analyzer.mock_generator import generate_mixed_scenario  # type: ignore[missing-import] # pyrefly: ignore
except (ImportError, ValueError):
    from parser import LogParser, LogEntry  # type: ignore[missing-import] # pyrefly: ignore
    from detector import LogAnalyzer  # type: ignore[missing-import] # pyrefly: ignore
    from server import LogAnalyzerServer  # type: ignore[missing-import] # pyrefly: ignore
    from mock_generator import generate_mixed_scenario  # type: ignore[missing-import] # pyrefly: ignore


class TestLogParser(unittest.TestCase):
    """Test suite for log parsing capabilities."""

    def setUp(self):
        self.parser = LogParser()

    def test_parse_standard_bracket_kv_format(self):
        line = '[2026-08-17T10:30:15Z] IP="192.168.1.105" METHOD="POST" ENDPOINT="/api/auth/login" STATUS=401 USER="admin" MSG="Login failed: Invalid credentials" USER_AGENT="Mozilla/5.0"'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.105")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.endpoint, "/api/auth/login")
        self.assertEqual(entry.status_code, 401)
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.message, "Login failed: Invalid credentials")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")
        self.assertTrue(entry.is_failed_login())
        self.assertFalse(entry.is_successful_login())
        self.assertIsNotNone(entry.timestamp.tzinfo)

    def test_parse_escaped_quotes_and_timezone_variants(self):
        line = '[2026-08-17 10:30:15] IP="192.168.1.10" METHOD="POST" ENDPOINT="/api/auth/login" STATUS=401 USER="sec_user" MSG="Login failed: User \\"admin\\" not found" USER_AGENT="curl/8.5"'
        entry = self.parser.parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.user, "sec_user")
        self.assertIn('"admin"', entry.message)
        self.assertIsNotNone(entry.timestamp.tzinfo)

    def test_parse_json_format(self):
        line = json.dumps({
            "timestamp": "2026-08-17T10:35:00Z",
            "ip": "10.0.0.99",
            "method": "GET",
            "endpoint": "/api/files/list",
            "status_code": 200,
            "user": "shahz",
            "message": "Files listed",
            "user_agent": "Chrome/122"
        })
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "10.0.0.99")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.user, "shahz")
        self.assertFalse(entry.is_failed_login())

    def test_parse_empty_and_comment_lines(self):
        self.assertIsNone(self.parser.parse_line(""))
        self.assertIsNone(self.parser.parse_line("   "))
        self.assertIsNone(self.parser.parse_line("# This is a comment"))

    def test_parse_file_gracefully_handles_missing(self):
        non_existent = "/tmp/does_not_exist_secureshare_12345.log"
        entries = self.parser.parse_file(non_existent)
        self.assertEqual(entries, [])


class TestThreatDetector(unittest.TestCase):
    """Test suite for threat detection rules and sliding window logic."""

    def setUp(self):
        self.analyzer = LogAnalyzer()
        self.base_time = datetime(2026, 8, 17, 10, 0, 0, tzinfo=timezone.utc)

    def test_brute_force_detected_when_exceeding_5_attempts_in_60s(self):
        """Rule: If an IP has >5 failed login attempts in 60s, flag BRUTE_FORCE_ATTACK."""
        entries = []
        for i in range(6):
            ts = self.base_time + timedelta(seconds=i * 5)
            entries.append(LogEntry(
                timestamp=ts,
                ip="198.51.100.42",
                method="POST",
                endpoint="/api/auth/login",
                status_code=401,
                user="admin",
                message="Login failed: Invalid credentials",
                user_agent="Hydra"
            ))

        alerts = self.analyzer.detect_brute_force(entries)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.alert_type, "BRUTE_FORCE_ATTACK")
        self.assertEqual(alert.ip, "198.51.100.42")
        self.assertEqual(alert.count, 6)
        self.assertEqual(alert.target_user, "admin")
        self.assertIn("198.51.100.42", alert.message)

    def test_brute_force_not_triggered_when_5_or_fewer_attempts(self):
        """Rule: Exactly 5 attempts (<= 5) must NOT trigger brute force alert."""
        entries = []
        for i in range(5):
            ts = self.base_time + timedelta(seconds=i * 5)
            entries.append(LogEntry(
                timestamp=ts,
                ip="198.51.100.42",
                method="POST",
                endpoint="/api/auth/login",
                status_code=401,
                user="admin",
                message="Login failed: Invalid credentials",
                user_agent="Hydra"
            ))

        alerts = self.analyzer.detect_brute_force(entries)
        self.assertEqual(len(alerts), 0)

    def test_brute_force_not_triggered_when_attempts_spread_outside_60s_window(self):
        """Rule: 6 attempts spread over 10 minutes (outside 60s window) must NOT trigger brute force alert."""
        entries = []
        for i in range(6):
            ts = self.base_time + timedelta(minutes=i * 2)
            entries.append(LogEntry(
                timestamp=ts,
                ip="198.51.100.42",
                method="POST",
                endpoint="/api/auth/login",
                status_code=401,
                user="admin",
                message="Login failed: Invalid credentials",
                user_agent="Browser"
            ))

        alerts = self.analyzer.detect_brute_force(entries)
        self.assertEqual(len(alerts), 0)

    def test_credential_stuffing_detection(self):
        """Rule: > 3 distinct users targeted with failed logins from 1 IP in 120s."""
        entries = []
        users = ["user1", "user2", "user3", "user4"]
        for i, u in enumerate(users):
            ts = self.base_time + timedelta(seconds=i * 10)
            entries.append(LogEntry(
                timestamp=ts,
                ip="203.0.113.88",
                method="POST",
                endpoint="/api/auth/login",
                status_code=401,
                user=u,
                message=f"Login failed for {u}",
                user_agent="Bot"
            ))

        alerts = self.analyzer.detect_credential_stuffing(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "CREDENTIAL_STUFFING")
        self.assertEqual(alerts[0].ip, "203.0.113.88")

    def test_path_traversal_and_sqli_detection(self):
        """Rule: Detect path traversal and SQL injection probe signatures."""
        entries = [
            LogEntry(
                timestamp=self.base_time,
                ip="198.51.100.99",
                method="GET",
                endpoint="/api/files/download?path=../../../../etc/passwd",
                status_code=400,
                user="anonymous",
                message="Directory traversal attempt",
                user_agent="Nikto"
            ),
            LogEntry(
                timestamp=self.base_time + timedelta(seconds=5),
                ip="198.51.100.99",
                method="POST",
                endpoint="/api/auth/login",
                status_code=400,
                user="anonymous",
                message="SQL Injection: ' OR 1=1 --",
                user_agent="SQLMap"
            ),
        ]

        alerts = self.analyzer.detect_web_attack_probing(entries)
        alert_types = {a.alert_type for a in alerts}
        self.assertIn("PATH_TRAVERSAL", alert_types)
        self.assertIn("SQL_INJECTION", alert_types)

    def test_url_encoded_path_traversal_and_sqli(self):
        """Rule: Detect URL-encoded path traversal and SQL injection payloads."""
        entries = [
            LogEntry(
                timestamp=self.base_time,
                ip="198.51.100.111",
                method="GET",
                endpoint="/api/files/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                status_code=400,
                user="anonymous",
                message="File access",
                user_agent="Scanner"
            ),
            LogEntry(
                timestamp=self.base_time + timedelta(seconds=2),
                ip="198.51.100.111",
                method="POST",
                endpoint="/api/auth/login?q=%27%20OR%20%271%27=%271",
                status_code=400,
                user="anonymous",
                message="Login request",
                user_agent="Scanner"
            ),
        ]

        alerts = self.analyzer.detect_web_attack_probing(entries)
        alert_types = {a.alert_type for a in alerts}
        self.assertIn("PATH_TRAVERSAL", alert_types)
        self.assertIn("SQL_INJECTION", alert_types)

    def test_rate_anomaly_detection(self):
        """Rule: > 30 requests in 10s window triggers RATE_ANOMALY."""
        entries = []
        for i in range(35):
            ts = self.base_time + timedelta(milliseconds=i * 200)
            entries.append(LogEntry(
                timestamp=ts,
                ip="198.51.100.200",
                method="GET",
                endpoint="/api/files/list",
                status_code=200,
                user="anonymous",
                message="List files",
                user_agent="FloodTool"
            ))

        alerts = self.analyzer.detect_rate_anomalies(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "RATE_ANOMALY")
        self.assertEqual(alerts[0].ip, "198.51.100.200")

    def test_statistics_calculation(self):
        """Test calculation of cybersecurity metrics for dashboard."""
        raw_logs = generate_mixed_scenario(self.base_time)
        parser = LogParser()
        entries = parser.parse_lines(raw_logs)
        alerts = self.analyzer.analyze(entries)
        stats = self.analyzer.get_statistics(entries, alerts)

        self.assertIn("summary", stats)
        self.assertIn("threat_breakdown", stats)
        self.assertIn("top_offending_ips", stats)
        self.assertIn("timeline", stats)
        self.assertGreater(stats["summary"]["total_requests"], 0)
        self.assertGreater(stats["summary"]["total_failed_logins"], 0)
        self.assertGreater(stats["summary"]["total_alerts"], 0)
        self.assertIn("BRUTE_FORCE_ATTACK", stats["threat_breakdown"])


class TestMockGenerator(unittest.TestCase):
    """Test suite for mock log generation and disk writing."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.temp_dir, "test_app_access.log")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_and_parse_mixed_scenario(self):
        base_time = datetime.now(timezone.utc)
        logs = generate_mixed_scenario(base_time)
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.writelines(logs)

        parser = LogParser(default_log_path=self.log_path)
        entries = parser.parse_file()
        self.assertGreaterEqual(len(entries), 50)

        analyzer = LogAnalyzer(parser)
        alerts = analyzer.analyze(entries)
        self.assertGreater(len(alerts), 0)

        alert_types = {a.alert_type for a in alerts}
        self.assertIn("BRUTE_FORCE_ATTACK", alert_types)


class TestAPIServer(unittest.TestCase):
    """Integration test suite for REST API endpoints and CORS."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.log_path = os.path.join(cls.temp_dir, "test_server_access.log")

        logs = generate_mixed_scenario(datetime.now(timezone.utc))
        with open(cls.log_path, "w", encoding="utf-8") as f:
            f.writelines(logs)

        cls.port = 58921
        cls.server = LogAnalyzerServer(host="127.0.0.1", port=cls.port, log_file=cls.log_path)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _get(self, path: str):
        url = f"http://127.0.0.1:{self.port}{path}"
        req = Request(url)
        with urlopen(req) as resp:
            headers = dict(resp.getheaders())
            body = resp.read().decode("utf-8")
            return resp.status, headers, json.loads(body)

    def test_health_endpoint(self):
        status, headers, data = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "SecureShare Cybersecurity Log Analyzer")
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")

    def test_stats_endpoint(self):
        status, headers, data = self._get("/api/stats")
        self.assertEqual(status, 200)
        self.assertIn("summary", data)
        self.assertIn("total_requests", data["summary"])
        self.assertIn("security_score", data["summary"])
        self.assertIn("threat_breakdown", data)
        self.assertIn("BRUTE_FORCE_ATTACK", data["threat_breakdown"])

    def test_alerts_endpoint_with_filtering(self):
        status, headers, data = self._get("/api/alerts")
        self.assertEqual(status, 200)
        self.assertIn("alerts", data)
        self.assertGreater(data["total"], 0)

        status, headers, data = self._get("/api/alerts?type=BRUTE_FORCE_ATTACK")
        self.assertEqual(status, 200)
        for alert in data["alerts"]:
            self.assertEqual(alert["alert_type"], "BRUTE_FORCE_ATTACK")

    def test_logs_endpoint_with_search(self):
        status, headers, data = self._get("/api/logs?limit=10")
        self.assertEqual(status, 200)
        self.assertIn("logs", data)
        self.assertLessEqual(len(data["logs"]), 10)

    def test_analyze_post_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/analyze"
        req = Request(url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 200)
            self.assertEqual(data["status"], "success")
            self.assertGreater(data["total_alerts"], 0)

    def test_options_cors_preflight(self):
        url = f"http://127.0.0.1:{self.port}/api/alerts"
        req = Request(url, method="OPTIONS")
        with urlopen(req) as resp:
            self.assertEqual(resp.status, 204)
            headers = dict(resp.getheaders())
            self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")


if __name__ == "__main__":
    unittest.main(verbosity=2)
