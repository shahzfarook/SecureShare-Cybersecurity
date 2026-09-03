"""
Mock Log Generator for SecureShare Cybersecurity
Author: Anfas
Generates realistic sample log entries into backend/logs/app_access.log for testing
the Log Analyzer, threat detection rules, and frontend dashboard integration.
"""

import argparse
from datetime import datetime, timedelta, timezone
import os
import random
import time
from typing import List, Optional


def resolve_log_path(custom_path: Optional[str] = None) -> str:
    """Resolve backend/logs/app_access.log path and ensure directory exists."""
    if custom_path:
        target = os.path.abspath(custom_path)
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        backend_dir = os.path.abspath(os.path.join(current_dir, ".."))
        target = os.path.join(backend_dir, "logs", "app_access.log")

    os.makedirs(os.path.dirname(target), exist_ok=True)
    return target


def format_log(
    timestamp: datetime,
    ip: str,
    method: str,
    endpoint: str,
    status_code: int,
    user: str,
    message: str,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
) -> str:
    """Format single log entry into standard tagged format."""
    ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f'[{ts_str}] IP="{ip}" METHOD="{method}" ENDPOINT="{endpoint}" '
        f'STATUS={status_code} USER="{user}" MSG="{message}" USER_AGENT="{user_agent}"\n'
    )


# Sample User Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "SecureShare-Client/1.2.0 (Linux; x86_64)",
    "curl/8.5.0",
    "python-requests/2.31.0"
]

LEGITIMATE_USERS = ["anfas", "shahz", "ahmed", "anuraj", "alice_sec", "bob_dev"]
NORMAL_IPS = ["192.168.1.50", "192.168.1.55", "10.0.0.12", "172.16.0.44", "192.168.1.120"]


def generate_brute_force_scenario(base_time: datetime, attacker_ip: str = "198.51.100.42", target_user: str = "admin", attempts: int = 8) -> List[str]:
    """Generate >5 failed logins in <60 seconds from one IP to trigger BRUTE_FORCE_ATTACK."""
    logs = []
    for i in range(attempts):
        ts = base_time - timedelta(seconds=(attempts - 1 - i) * 3)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method="POST",
            endpoint="/api/auth/login",
            status_code=401,
            user=target_user,
            message="Login failed: Invalid credentials provided",
            user_agent="python-requests/2.31.0 (Hydra-Attack-Tool)"
        ))
    return logs


def generate_credential_stuffing_scenario(base_time: datetime, attacker_ip: str = "203.0.113.88") -> List[str]:
    """Generate rapid failed logins across multiple users to trigger CREDENTIAL_STUFFING."""
    logs = []
    users = ["root", "admin", "administrator", "ahmed", "anuraj", "shahz", "anfas"]
    for i, u in enumerate(users):
        ts = base_time - timedelta(seconds=(len(users) - 1 - i) * 4)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method="POST",
            endpoint="/api/auth/login",
            status_code=401,
            user=u,
            message=f"Login failed: Incorrect password for user '{u}'",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bot/1.0"
        ))
    return logs


def generate_path_traversal_scenario(base_time: datetime, attacker_ip: str = "198.51.100.77") -> List[str]:
    """Generate path traversal probe logs."""
    logs = []
    probes = [
        ("GET", "/api/files/download?path=../../../../etc/passwd", 400, "Blocked directory traversal attempt"),
        ("GET", "/.env", 404, "Attempted access to sensitive configuration file"),
        ("GET", "/.git/config", 404, "Attempted access to git repository metadata"),
        ("GET", "/api/files/view?file=..%2f..%2f..%2fetc%2fshadow", 400, "Encoded traversal blocked"),
    ]
    for i, (m, ep, code, msg) in enumerate(probes):
        ts = base_time - timedelta(seconds=(len(probes) - 1 - i) * 3)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method=m,
            endpoint=ep,
            status_code=code,
            user="anonymous",
            message=msg,
            user_agent="Nikto/2.1.6 (Security Scanner)"
        ))
    return logs


def generate_sqli_scenario(base_time: datetime, attacker_ip: str = "198.51.100.99") -> List[str]:
    """Generate SQL injection probe logs."""
    logs = []
    probes = [
        ("POST", "/api/auth/login", 400, "SQL Injection attempt: ' OR '1'='1"),
        ("GET", "/api/files/search?query=1%20UNION%20SELECT%20null,username,password%20FROM%20users", 400, "SQL Injection payload: UNION SELECT"),
        ("POST", "/api/auth/token", 400, "SQL Injection attempt: admin' --"),
    ]
    for i, (m, ep, code, msg) in enumerate(probes):
        ts = base_time - timedelta(seconds=(len(probes) - 1 - i) * 3)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method=m,
            endpoint=ep,
            status_code=code,
            user="anonymous",
            message=msg,
            user_agent="sqlmap/1.7.2#stable"
        ))
    return logs


def generate_web_probe_scenario(base_time: datetime, attacker_ip: str = "198.51.100.99") -> List[str]:
    """Generate directory traversal and web vulnerability probe signatures."""
    logs = []
    probes = [
        ("GET", "/api/files/download?path=../../../../etc/passwd", 400, "Blocked directory traversal attempt"),
        ("GET", "/.env", 404, "Attempted access to sensitive configuration file"),
        ("GET", "/.git/config", 404, "Attempted access to git repository metadata"),
        ("POST", "/api/auth/login", 400, "SQL Injection attempt: ' OR '1'='1"),
        ("GET", "/api/files/search?q=<script>alert('XSS')</script>", 400, "XSS script payload detected"),
        ("GET", "/wp-login.php", 404, "Probing for CMS management interfaces"),
    ]
    for i, (m, ep, code, msg) in enumerate(probes):
        ts = base_time - timedelta(seconds=(len(probes) - 1 - i) * 4)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method=m,
            endpoint=ep,
            status_code=code,
            user="anonymous",
            message=msg,
            user_agent="Nikto/2.1.6 (Security Scanner)"
        ))
    return logs


def generate_rate_anomaly_scenario(base_time: datetime, attacker_ip: str = "198.51.100.200", count: int = 35) -> List[str]:
    """Generate 35 rapid requests in 5 seconds to trigger RATE_ANOMALY."""
    logs = []
    for i in range(count):
        ts = base_time - timedelta(milliseconds=(count - 1 - i) * 100)
        logs.append(format_log(
            timestamp=ts,
            ip=attacker_ip,
            method="GET",
            endpoint=f"/api/files/view?id={100 + i}",
            status_code=200 if i < 15 else 429,
            user="anonymous",
            message="File view request" if i < 15 else "Rate limit exceeded (HTTP 429)",
            user_agent="DDoS-Flood-Tool/1.0"
        ))
    return logs


def generate_normal_traffic(base_time: datetime, count: int = 30) -> List[str]:
    """Generate legitimate, normal operational traffic for SecureShare."""
    logs = []
    normal_actions = [
        ("POST", "/api/auth/login", 200, "Login successful: Session established"),
        ("GET", "/api/auth/profile", 200, "User profile retrieved"),
        ("GET", "/api/files/list", 200, "File directory listed"),
        ("POST", "/api/files/upload", 201, "Encrypted file uploaded successfully"),
        ("GET", "/api/files/download/report_2026.pdf", 200, "Encrypted file decrypted and downloaded"),
        ("POST", "/api/files/share", 200, "Secure link generated with expiration"),
        ("POST", "/api/auth/refresh", 200, "Access token refreshed"),
        ("GET", "/api/health", 200, "System health ok")
    ]

    for i in range(count):
        ts = base_time + timedelta(seconds=i * random.randint(10, 45))
        m, ep, code, msg = random.choice(normal_actions)
        user = random.choice(LEGITIMATE_USERS)
        ip = random.choice(NORMAL_IPS)
        ua = random.choice(USER_AGENTS)
        logs.append(format_log(
            timestamp=ts,
            ip=ip,
            method=m,
            endpoint=ep,
            status_code=code,
            user=user,
            message=msg,
            user_agent=ua
        ))
    return logs


def generate_mixed_scenario(base_time: datetime, total_approx: int = 60) -> List[str]:
    """Generate a realistic mix of normal traffic, brute force attacks, and probes."""
    all_logs = []
    all_logs.extend(generate_normal_traffic(base_time - timedelta(minutes=20), count=25))
    all_logs.extend(generate_brute_force_scenario(base_time - timedelta(minutes=10), attacker_ip="198.51.100.42", target_user="admin", attempts=8))
    all_logs.extend(generate_credential_stuffing_scenario(base_time - timedelta(minutes=7), attacker_ip="203.0.113.88"))
    all_logs.extend(generate_web_probe_scenario(base_time - timedelta(minutes=4), attacker_ip="198.51.100.99"))
    all_logs.extend(generate_normal_traffic(base_time - timedelta(minutes=3), count=15))

    def extract_ts(log_str: str) -> datetime:
        try:
            ts_str = log_str.split("]")[0][1:]
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    all_logs.sort(key=extract_ts)
    return all_logs


def stream_logs(log_path: str, delay: float = 1.0):
    """Continuously stream generated logs into log file with live delays."""
    print(f"[Mock Generator] Streaming live logs to {log_path} (delay: {delay}s)...")
    print("[Mock Generator] Press Ctrl+C to stop.")

    cycle = 0
    try:
        while True:
            cycle += 1
            now = datetime.now(timezone.utc)
            if cycle % 10 == 0:
                print(f"[Mock Generator] Emitting BRUTE_FORCE_ATTACK burst from 198.51.100.42...")
                entries = generate_brute_force_scenario(now, attempts=6)
            elif cycle % 7 == 0:
                print(f"[Mock Generator] Emitting WEB_ATTACK_PROBING from 198.51.100.99...")
                entries = generate_web_probe_scenario(now)
            else:
                entries = generate_normal_traffic(now, count=1)

            with open(log_path, "a", encoding="utf-8") as f:
                for line in entries:
                    f.write(line)
                    f.flush()
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[Mock Generator] Stream stopped.")


def main():
    parser = argparse.ArgumentParser(description="SecureShare Cybersecurity Mock Log Generator")
    parser.add_argument(
        "--scenario", "-s",
        choices=["mixed", "brute_force", "credential_stuffing", "traversal", "rate_anomaly", "normal"],
        default="mixed",
        help="Attack scenario to generate (default: mixed)"
    )
    parser.add_argument("--count", "-n", type=int, default=50, help="Number of normal log entries to generate")
    parser.add_argument("--output", "-o", help="Custom output log file path")
    parser.add_argument("--append", "-a", action="store_true", help="Append to log file instead of overwriting")
    parser.add_argument("--clean", action="store_true", help="Clear the target log file and exit")
    parser.add_argument("--stream", action="store_true", help="Continuously stream logs in real-time")
    parser.add_argument("--delay", "-d", type=float, default=1.0, help="Delay between streamed entries (seconds)")

    args = parser.parse_args()
    log_path = resolve_log_path(args.output)

    if args.clean:
        with open(log_path, "w", encoding="utf-8") as f:
            pass
        print(f"[Mock Generator] Cleared log file: {log_path}")
        return

    if args.stream:
        stream_logs(log_path, delay=args.delay)
        return

    base_time = datetime.now(timezone.utc)
    if args.scenario == "brute_force":
        logs = generate_brute_force_scenario(base_time, attempts=8)
    elif args.scenario == "credential_stuffing":
        logs = generate_credential_stuffing_scenario(base_time)
    elif args.scenario == "traversal":
        logs = generate_web_probe_scenario(base_time)
    elif args.scenario == "rate_anomaly":
        logs = generate_rate_anomaly_scenario(base_time)
    elif args.scenario == "normal":
        logs = generate_normal_traffic(base_time, count=args.count)
    else:
        logs = generate_mixed_scenario(base_time, total_approx=args.count)

    mode = "a" if args.append else "w"
    with open(log_path, mode, encoding="utf-8") as f:
        f.writelines(logs)

    print(f"[Mock Generator] Successfully wrote {len(logs)} entries to: {log_path}")
    print(f"[Mock Generator] Scenario: '{args.scenario}' | Mode: '{'append' if args.append else 'overwrite'}'")


if __name__ == "__main__":
    main()
