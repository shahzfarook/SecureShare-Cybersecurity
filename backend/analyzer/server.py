"""
REST API Server for SecureShare Cybersecurity Log Analyzer
Author: Anfas
Provides multi-threaded HTTP endpoints (/api/alerts, /api/stats, /api/logs, /api/health, /api/analyze)
with full CORS support for frontend consumption.
"""

from http.server import BaseHTTPRequestHandler
import json
import os
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from http.server import ThreadingHTTPServer as BaseHTTPServer
except ImportError:
    from http.server import HTTPServer as BaseHTTPServer

import sys

_analyzer_dir = os.path.dirname(os.path.abspath(__file__))
if _analyzer_dir not in sys.path:
    sys.path.insert(0, _analyzer_dir)

try:
    from .parser import LogParser  # type: ignore[missing-import] # pyrefly: ignore
    from .detector import LogAnalyzer  # type: ignore[missing-import] # pyrefly: ignore
    from .mock_generator import (  # type: ignore[missing-import] # pyrefly: ignore
        generate_brute_force_scenario,
        generate_credential_stuffing_scenario,
        generate_path_traversal_scenario,
        generate_sqli_scenario,
        generate_mixed_scenario,
        resolve_log_path,
    )
except (ImportError, ValueError):
    from parser import LogParser  # type: ignore[missing-import] # pyrefly: ignore
    from detector import LogAnalyzer  # type: ignore[missing-import] # pyrefly: ignore
    from mock_generator import (  # type: ignore[missing-import] # pyrefly: ignore
        generate_brute_force_scenario,
        generate_credential_stuffing_scenario,
        generate_path_traversal_scenario,
        generate_sqli_scenario,
        generate_mixed_scenario,
        resolve_log_path,
    )


class AnalyzerAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Log Analyzer REST endpoints with CORS support."""

    analyzer: LogAnalyzer = LogAnalyzer()
    log_file_path: Optional[str] = None

    def _set_headers(self, status_code: int = 200, content_type: str = "application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        # Enable CORS for frontend integration
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_OPTIONS(self):
        """Handle CORS pre-flight requests."""
        self._set_headers(204, "text/plain")

    def _send_json(self, data: Any, status_code: int = 200):
        """Helper to send JSON response."""
        self._set_headers(status_code, "application/json")
        response_body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.wfile.write(response_body)

    def _send_error(self, message: str, status_code: int = 400):
        """Helper to send structured JSON error."""
        self._send_json({"error": message, "status": status_code}, status_code=status_code)

    def do_GET(self):
        """Handle GET requests."""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")
            query_params = parse_qs(parsed_url.query)

            # 1. Health Check
            if path in ("/api/health", "/health"):
                target_log = self.log_file_path or self.analyzer.parser.default_log_path
                self._send_json({
                    "status": "healthy",
                    "service": "SecureShare Cybersecurity Log Analyzer",
                    "version": "1.0.0",
                    "author": "Anfas",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "log_source": target_log,
                    "log_source_exists": os.path.exists(target_log)
                })
                return

            # 2. Security Alerts Endpoint
            if path in ("/api/alerts", "/alerts"):
                entries = self.analyzer.parser.parse_file(self.log_file_path)
                alerts = self.analyzer.analyze(entries)

                severity_filter = query_params.get("severity", [None])[0]
                if severity_filter:
                    severities = [s.strip().upper() for s in severity_filter.split(",")]
                    alerts = [a for a in alerts if a.severity in severities]

                type_filter = query_params.get("type", [None])[0]
                if type_filter:
                    types = [t.strip().upper() for t in type_filter.split(",")]
                    alerts = [a for a in alerts if a.alert_type in types]

                ip_filter = query_params.get("ip", [None])[0]
                if ip_filter:
                    alerts = [a for a in alerts if a.ip == ip_filter.strip()]

                try:
                    limit = max(1, min(1000, int(query_params.get("limit", [50])[0])))
                    offset = max(0, int(query_params.get("offset", [0])[0]))
                except ValueError:
                    limit, offset = 50, 0

                paginated_alerts = alerts[offset: offset + limit]

                self._send_json({
                    "alerts": [a.to_dict() for a in paginated_alerts],
                    "total": len(alerts),
                    "limit": limit,
                    "offset": offset,
                    "filters_applied": {
                        "severity": severity_filter,
                        "type": type_filter,
                        "ip": ip_filter
                    }
                })
                return

            # 3. Security Statistics & Metrics Dashboard Endpoint
            if path in ("/api/stats", "/stats"):
                entries = self.analyzer.parser.parse_file(self.log_file_path)
                alerts = self.analyzer.analyze(entries)
                stats = self.analyzer.get_statistics(entries, alerts)
                self._send_json(stats)
                return

            # 4. Parsed Access Logs Explorer Endpoint
            if path in ("/api/logs", "/logs"):
                entries = self.analyzer.parser.parse_file(self.log_file_path)

                search_query = query_params.get("search", [None])[0]
                if search_query:
                    sq = search_query.lower()
                    entries = [
                        e for e in entries
                        if sq in e.ip.lower()
                        or sq in e.user.lower()
                        or sq in e.endpoint.lower()
                        or sq in e.message.lower()
                    ]

                status_filter = query_params.get("status", [None])[0]
                if status_filter:
                    try:
                        sc = int(status_filter)
                        entries = [e for e in entries if e.status_code == sc]
                    except ValueError:
                        pass

                ip_filter = query_params.get("ip", [None])[0]
                if ip_filter:
                    entries = [e for e in entries if e.ip == ip_filter.strip()]

                entries = list(reversed(entries))

                try:
                    limit = max(1, min(1000, int(query_params.get("limit", [50])[0])))
                    offset = max(0, int(query_params.get("offset", [0])[0]))
                except ValueError:
                    limit, offset = 50, 0

                paginated_entries = entries[offset: offset + limit]

                self._send_json({
                    "logs": [e.to_dict() for e in paginated_entries],
                    "total": len(entries),
                    "limit": limit,
                    "offset": offset
                })
                return

            # 5. Root Index Info
            if path in ("", "/"):
                self._send_json({
                    "name": "SecureShare Cybersecurity Log Analyzer API",
                    "developer": "Anfas",
                    "status": "online",
                    "endpoints": {
                        "GET /api/health": "Health check and system status",
                        "GET /api/alerts": "List security alerts (params: severity, type, ip, limit, offset)",
                        "GET /api/stats": "Security statistics, threat breakdown, and timeline metrics",
                        "GET /api/logs": "Parsed log viewer with search, status, and IP filters",
                        "POST /api/analyze": "Trigger on-demand re-scan of log file"
                    }
                })
                return

            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            self._send_error(f"Internal server error: {str(e)}", status_code=500)

    def do_POST(self):
        """Handle POST requests."""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path.rstrip("/")

            if path in ("/api/analyze", "/analyze"):
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length > 0:
                    _ = self.rfile.read(content_length)

                entries = self.analyzer.parser.parse_file(self.log_file_path)
                alerts = self.analyzer.analyze(entries)
                stats = self.analyzer.get_statistics(entries, alerts)
                self._send_json({
                    "status": "success",
                    "message": f"Successfully analyzed {len(entries)} log entries. Identified {len(alerts)} alerts.",
                    "total_alerts": len(alerts),
                    "summary": stats["summary"]
                })
                return

            if path in ("/api/simulate", "/simulate"):
                content_length = int(self.headers.get("Content-Length", 0))
                body = {}
                if content_length > 0:
                    try:
                        raw_body = self.rfile.read(content_length)
                        body = json.loads(raw_body.decode("utf-8"))
                    except Exception:
                        body = {}

                attack_type = body.get("attack_type", "all").lower()
                target_path = self.log_file_path or self.analyzer.parser.default_log_path
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                now = datetime.now(timezone.utc)

                lines_to_write = []
                if attack_type == "brute_force":
                    lines_to_write = generate_brute_force_scenario(now, attacker_ip="198.51.100.42", target_user="admin", attempts=8)
                elif attack_type == "sqli":
                    lines_to_write = generate_sqli_scenario(now, attacker_ip="198.51.100.99")
                elif attack_type == "credential_stuffing":
                    lines_to_write = generate_credential_stuffing_scenario(now, attacker_ip="203.0.113.88")
                elif attack_type == "path_traversal":
                    lines_to_write = generate_path_traversal_scenario(now, attacker_ip="198.51.100.77")
                else:  # "all" or mixed
                    lines_to_write = generate_mixed_scenario(now)

                with open(target_path, "a", encoding="utf-8") as f:
                    for line in lines_to_write:
                        f.write(line)

                # Re-analyze immediately
                entries = self.analyzer.parser.parse_file(target_path)
                alerts = self.analyzer.analyze(entries)
                stats = self.analyzer.get_statistics(entries, alerts)

                self._send_json({
                    "status": "success",
                    "simulated_attack": attack_type,
                    "injected_logs_count": len(lines_to_write),
                    "total_alerts": len(alerts),
                    "message": f"Successfully injected {len(lines_to_write)} simulated attack logs for '{attack_type.upper()}'. Threat engine identified {len(alerts)} total alerts.",
                    "summary": stats["summary"]
                })
                return

            if path in ("/api/clear-logs", "/clear-logs"):
                target_path = self.log_file_path or self.analyzer.parser.default_log_path
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write("")

                self._send_json({
                    "status": "success",
                    "message": "Access logs cleared successfully. Threat Engine reset.",
                    "total_alerts": 0
                })
                return

            self._send_error(f"Endpoint '{path}' not found", status_code=404)

        except Exception as e:
            self._send_error(f"Internal server error: {str(e)}", status_code=500)

    def log_message(self, format_str, *args):
        """Suppress standard HTTP server request noise unless in debug mode."""
        return


DEFAULT_ANALYZER_PORT = int(os.environ.get("ANALYZER_PORT", "5001"))


class LogAnalyzerServer:
    """Multi-threaded REST API server for Log Analyzer."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_ANALYZER_PORT, log_file: Optional[str] = None):
        self.host = host
        self.port = port
        self.log_file = log_file
        self.analyzer = LogAnalyzer(LogParser(default_log_path=log_file))
        AnalyzerAPIHandler.log_file_path = log_file
        AnalyzerAPIHandler.analyzer = self.analyzer
        self.httpd = BaseHTTPServer((self.host, self.port), AnalyzerAPIHandler)

    def start(self):
        """Start the HTTP server (blocking)."""
        print(f"[SecureShare Log Analyzer] Server started at http://{self.host}:{self.port}")
        print(f"[SecureShare Log Analyzer] Monitoring log file: {self.analyzer.parser.default_log_path}")
        print("[SecureShare Log Analyzer] Press Ctrl+C to stop.")
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SecureShare Log Analyzer] Shutting down server gracefully...")
        finally:
            self.httpd.server_close()

    def shutdown(self):
        """Programmatically shutdown the server."""
        self.httpd.shutdown()
        self.httpd.server_close()


def run_server(host: str = "0.0.0.0", port: int = DEFAULT_ANALYZER_PORT, log_file: Optional[str] = None):
    """Convenience function to run the server."""
    server = LogAnalyzerServer(host=host, port=port, log_file=log_file)
    server.start()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureShare Cybersecurity Log Analyzer API Server")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_ANALYZER_PORT, help=f"Port to listen on (default: {DEFAULT_ANALYZER_PORT})")
    parser.add_argument("--log-file", help="Custom path to access log file")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, log_file=args.log_file)

