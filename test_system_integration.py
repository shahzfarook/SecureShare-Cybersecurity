#!/usr/bin/env python3
"""
SecureShare Cybersecurity - System Integration Test Suite
Tests log parsing, threat detection algorithms, and signature analysis
against real-world and mock attack logs in backend/logs/app_access.log.

Run with:
    python3 -m unittest test_system_integration.py -v
"""

import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure project root is in sys.path
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

_ANALYZER_DIR = os.path.join(_PROJECT_ROOT, "backend", "analyzer")
if _ANALYZER_DIR not in sys.path:
    sys.path.insert(0, _ANALYZER_DIR)

from backend.analyzer.parser import LogParser, LogEntry
from backend.analyzer.detector import LogAnalyzer, SecurityAlert
from backend.analyzer.mock_generator import generate_mixed_scenario


class TestSystemIntegration(unittest.TestCase):
    """Integration test suite for SecureShare log parser and threat detection engine."""

    @classmethod
    def setUpClass(cls):
        """Set up log file path and ensure test log data exists."""
        cls.log_path = os.path.join(_PROJECT_ROOT, "backend", "logs", "app_access.log")
        cls.parser = LogParser(default_log_path=cls.log_path)
        cls.analyzer = LogAnalyzer(parser=cls.parser)

        # Ensure directory exists
        os.makedirs(os.path.dirname(cls.log_path), exist_ok=True)

        # If log file does not exist or has fewer than 20 entries, seed it with mixed scenario
        needs_seed = True
        if os.path.exists(cls.log_path):
            existing_entries = cls.parser.parse_file(cls.log_path)
            # Check if key attacker IPs are present
            ips = {e.ip for e in existing_entries}
            if "198.51.100.42" in ips and "203.0.113.88" in ips and "198.51.100.99" in ips:
                needs_seed = False

        if needs_seed:
            now = datetime.now(timezone.utc)
            sample_logs = generate_mixed_scenario(now)
            with open(cls.log_path, "w", encoding="utf-8") as f:
                f.writelines(sample_logs)

    def setUp(self):
        """Parse log file before each test."""
        self.entries = self.parser.parse_file(self.log_path)
        self.assertGreater(len(self.entries), 0, "Log file must contain parsed entries")

    def test_1_bracketed_kv_log_parsing(self):
        """
        Test Parsing:
        Parse bracketed Key-Value log entries matching our log pattern:
        [TIMESTAMP] IP="..." METHOD="..." ENDPOINT="..." STATUS=... USER="..." MSG="..." USER_AGENT="..."
        """
        sample_line = (
            '[2026-08-31T10:30:15Z] IP="192.168.1.105" METHOD="POST" ENDPOINT="/api/auth/login" '
            'STATUS=401 USER="admin" MSG="Login failed: Invalid credentials provided" '
            'USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'
        )
        entry = self.parser.parse_line(sample_line)
        self.assertIsNotNone(entry, "Parser should successfully parse bracketed KV format")
        self.assertEqual(entry.ip, "192.168.1.105")
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.endpoint, "/api/auth/login")
        self.assertEqual(entry.status_code, 401)
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.message, "Login failed: Invalid credentials provided")
        self.assertEqual(entry.user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        self.assertTrue(entry.is_failed_login(), "Status 401 on /api/auth/login must be recognized as failed login")
        self.assertFalse(entry.is_successful_login(), "Status 401 must not be marked as successful login")
        self.assertIsNotNone(entry.timestamp.tzinfo, "Parsed timestamp must be timezone-aware")

        # Verify parsed entries from app_access.log
        valid_entries = [e for e in self.entries if isinstance(e, LogEntry)]
        self.assertEqual(len(valid_entries), len(self.entries))
        for e in self.entries:
            self.assertTrue(bool(e.ip), "Parsed entry must have IP")
            self.assertTrue(bool(e.method), "Parsed entry must have HTTP method")
            self.assertTrue(bool(e.endpoint), "Parsed entry must have endpoint")
            self.assertIsInstance(e.status_code, int, "Status code must be integer")

    def test_2_hydra_brute_force_detection(self):
        """
        Test Hydra Brute-Force Detection:
        Verify detection of >= 5 failed logins from IP 198.51.100.42.
        """
        # Filter entries for the brute force attacker IP
        hydra_entries = [e for e in self.entries if e.ip == "198.51.100.42" and e.is_failed_login()]
        self.assertGreaterEqual(
            len(hydra_entries), 5,
            f"Expected at least 5 failed login entries for 198.51.100.42, found {len(hydra_entries)}"
        )

        alerts = self.analyzer.detect_brute_force(self.entries)
        brute_force_alerts = [a for a in alerts if a.ip == "198.51.100.42" and a.alert_type == "BRUTE_FORCE_ATTACK"]

        self.assertGreaterEqual(
            len(brute_force_alerts), 1,
            "Engine must trigger BRUTE_FORCE_ATTACK alert for IP 198.51.100.42"
        )
        alert = brute_force_alerts[0]
        self.assertEqual(alert.ip, "198.51.100.42")
        self.assertEqual(alert.alert_type, "BRUTE_FORCE_ATTACK")
        self.assertGreaterEqual(alert.count, 5)
        self.assertIn(alert.severity, ("CRITICAL", "HIGH"))
        self.assertEqual(alert.target_user, "admin")
        self.assertIn("198.51.100.42", alert.message)
        self.assertGreater(len(alert.evidence), 0)

    def test_3_user_enumeration_and_spray_detection(self):
        """
        Test User Enumeration/Spray:
        Verify detection of multiple failed logins across different usernames from IP 203.0.113.88.
        """
        spray_entries = [e for e in self.entries if e.ip == "203.0.113.88" and e.is_failed_login()]
        distinct_users = {e.user for e in spray_entries if e.user not in ("", "anonymous", "unknown")}
        self.assertGreater(
            len(distinct_users), 3,
            f"Expected > 3 distinct users for spray IP 203.0.113.88, found {len(distinct_users)}"
        )

        alerts = self.analyzer.detect_credential_stuffing(self.entries)
        spray_alerts = [a for a in alerts if a.ip == "203.0.113.88" and a.alert_type == "CREDENTIAL_STUFFING"]

        self.assertGreaterEqual(
            len(spray_alerts), 1,
            "Engine must trigger CREDENTIAL_STUFFING alert for spray IP 203.0.113.88"
        )
        alert = spray_alerts[0]
        self.assertEqual(alert.ip, "203.0.113.88")
        self.assertEqual(alert.alert_type, "CREDENTIAL_STUFFING")
        self.assertIn(alert.severity, ("CRITICAL", "HIGH"))
        self.assertGreaterEqual(alert.count, 4)
        self.assertIn("Credential stuffing detected", alert.message)

    def test_4_web_scan_and_injection_probing(self):
        """
        Test Web Scans:
        Verify detection of Nikto scanner activity, directory traversal (etc/passwd),
        and SQL injection attempts from IP 198.51.100.99.
        """
        scan_entries = [e for e in self.entries if e.ip == "198.51.100.99"]
        self.assertGreater(len(scan_entries), 0, "Log entries for 198.51.100.99 must exist")

        # Verify Nikto scanner user-agent presence
        nikto_entries = [e for e in scan_entries if "Nikto" in e.user_agent]
        self.assertGreater(len(nikto_entries), 0, "Nikto user-agent must be present in scan entries")

        # Run threat detection for web probing
        alerts = self.analyzer.detect_web_attack_probing(self.entries)
        probes_for_ip = [a for a in alerts if a.ip == "198.51.100.99"]
        alert_types = {a.alert_type for a in probes_for_ip}

        self.assertIn(
            "PATH_TRAVERSAL", alert_types,
            "Engine must detect PATH_TRAVERSAL (/etc/passwd probe) for IP 198.51.100.99"
        )
        self.assertIn(
            "SQL_INJECTION", alert_types,
            "Engine must detect SQL_INJECTION payload for IP 198.51.100.99"
        )

        # Validate aggregate threat statistics
        all_alerts = self.analyzer.analyze(self.entries)
        stats = self.analyzer.get_statistics(self.entries, all_alerts)
        self.assertIn("PATH_TRAVERSAL", stats["threat_breakdown"])
        self.assertIn("SQL_INJECTION", stats["threat_breakdown"])
        self.assertGreater(stats["summary"]["total_alerts"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
