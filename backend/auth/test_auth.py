"""
Unit and Integration Test Suite for SecureShare Authentication & Access Control Module
Author: Anuraj / QA Team
Run with: pytest backend/auth/ or python -m unittest discover -s backend/auth
"""

from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import sys
import tempfile
import unittest

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import jwt
    from pydantic import ValidationError
    AUTH_DEPS_AVAILABLE = True
except ImportError:
    FastAPI = None
    TestClient = None
    jwt = None
    ValidationError = None
    AUTH_DEPS_AVAILABLE = False

# Ensure project root and backend are in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

_backend_dir = os.path.abspath(os.path.join(_current_dir, ".."))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

_project_root = os.path.abspath(os.path.join(_backend_dir, ".."))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

try:
    from backend.auth.models import (
        UserRole,
        UserRegisterRequest,
        UserLoginRequest,
        UserResponse,
        TokenResponse,
        TokenPayload,
        RoleUpdateRequest,
        LoginAttemptLog,
    )
    from backend.auth.security import (
        hash_password,
        verify_password,
        create_access_token,
        create_refresh_token,
        decode_token,
    )
    from backend.auth.storage import (
        user_repository,
        UserRecord,
        UserRepository,
    )
    from backend.auth.logger import (
        log_login_attempt,
    )
    from backend.auth.router import (
        auth_router,
    )
    from backend.auth.config import (
        SECRET_KEY,
        ALGORITHM,
        ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    from backend.analyzer.parser import LogParser, LogEntry
    from backend.analyzer.detector import LogAnalyzer
except (ImportError, ValueError):
    UserRole = None
    UserRegisterRequest = None
    UserLoginRequest = None
    UserResponse = None
    TokenResponse = None
    TokenPayload = None
    RoleUpdateRequest = None
    LoginAttemptLog = None
    hash_password = None
    verify_password = None
    create_access_token = None
    create_refresh_token = None
    decode_token = None
    user_repository = None
    UserRecord = None
    UserRepository = None
    log_login_attempt = None
    auth_router = None
    SECRET_KEY = None
    ALGORITHM = None
    ACCESS_TOKEN_EXPIRE_MINUTES = None
    LogParser = None
    LogEntry = None
    LogAnalyzer = None
    AUTH_DEPS_AVAILABLE = False


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestUserModels(unittest.TestCase):
    """Test validation and behavior of Pydantic models in auth/models.py."""

    def test_valid_user_register_request(self):
        req = UserRegisterRequest(
            name="Alice QA",
            username="alice",
            email="Alice@Example.com",
            password="SecurePassword123!",
            role=UserRole.USER,
        )
        self.assertEqual(req.email, "alice@example.com")
        self.assertEqual(req.username, "alice")
        self.assertEqual(req.role, UserRole.USER)

    def test_invalid_email_format_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            UserRegisterRequest(
                email="not-an-email",
                password="validpassword123",
            )

    def test_empty_email_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            UserRegisterRequest(
                email="",
                password="validpassword123",
            )

    def test_short_password_raises_validation_error(self):
        with self.assertRaises(ValidationError):
            UserRegisterRequest(
                email="alice@example.com",
                password="123",  # < 6 chars
            )

    def test_user_login_request_lowercasing(self):
        req = UserLoginRequest(
            email=" Alice@Example.COM ",
            password="mypassword",
        )
        self.assertEqual(req.email, "alice@example.com")

    def test_login_attempt_log_model(self):
        audit = LoginAttemptLog(
            Timestamp="2026-08-20T10:00:00Z",
            Username="admin",
            Status="SUCCESS",
            IP="192.168.1.10",
        )
        self.assertEqual(audit.Username, "admin")
        self.assertEqual(audit.Status, "SUCCESS")
        self.assertEqual(audit.StatusCode, 200)


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestPasswordSecurity(unittest.TestCase):
    """Test bcrypt hashing, salting, and constant-time password verification."""

    def test_password_hashing_and_verification_success(self):
        plain = "SuperSecretP@ss123"
        hashed = hash_password(plain)

        self.assertIsInstance(hashed, str)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("$2a$"))
        self.assertTrue(verify_password(plain, hashed))

    def test_incorrect_password_fails_verification(self):
        plain = "CorrectPassword123"
        hashed = hash_password(plain)
        self.assertFalse(verify_password("WrongPassword456", hashed))

    def test_empty_and_none_password_handling(self):
        hashed = hash_password("ValidPassword")
        self.assertFalse(verify_password("", hashed))
        self.assertFalse(verify_password(None, hashed))  # type: ignore
        self.assertFalse(verify_password("ValidPassword", ""))


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestJWTTokens(unittest.TestCase):
    """Test JWT creation, claim injection, decoding, and expiration."""

    def test_create_and_decode_valid_access_token(self):
        claims = {
            "sub": "user-12345",
            "email": "tester@secureshare.local",
            "username": "tester",
            "role": "admin",
        }
        token = create_access_token(claims)
        self.assertIsInstance(token, str)

        decoded = decode_token(token)
        self.assertEqual(decoded["sub"], "user-12345")
        self.assertEqual(decoded["email"], "tester@secureshare.local")
        self.assertEqual(decoded["username"], "tester")
        self.assertEqual(decoded["role"], "admin")
        self.assertIn("exp", decoded)
        self.assertIn("iat", decoded)

    def test_expired_token_raises_expired_signature_error(self):
        claims = {"sub": "user-expired", "role": "user"}
        expired_token = create_access_token(claims, expires_delta=timedelta(seconds=-10))

        with self.assertRaises(jwt.ExpiredSignatureError):
            decode_token(expired_token)

    def test_invalid_token_raises_invalid_token_error(self):
        with self.assertRaises(jwt.InvalidTokenError):
            decode_token("this.is.an.invalid.token")

    def test_create_refresh_token_has_refresh_type(self):
        claims = {"sub": "user-refresh"}
        refresh_token = create_refresh_token(claims)
        decoded = decode_token(refresh_token)
        self.assertEqual(decoded["type"], "refresh")


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestUserRepository(unittest.TestCase):
    """Test thread-safe user repository CRUD operations."""

    def setUp(self):
        user_repository.clear()

    def test_default_seeded_accounts_exist(self):
        admin = user_repository.get_by_username("admin")
        self.assertIsNotNone(admin)
        self.assertEqual(admin.role, UserRole.ADMIN)
        self.assertTrue(verify_password("Admin@123456", admin.hashed_password))

        user = user_repository.get_by_username("user")
        self.assertIsNotNone(user)
        self.assertEqual(user.role, UserRole.USER)
        self.assertTrue(verify_password("User@123456", user.hashed_password))

    def test_create_new_user_success(self):
        new_user = user_repository.create_user(
            email="qa_lead@secureshare.local",
            password="SecurePass999!",
            username="qalead",
            name="QA Lead Architect",
            role=UserRole.ADMIN,
        )
        self.assertEqual(new_user.username, "qalead")
        self.assertEqual(new_user.email, "qa_lead@secureshare.local")
        self.assertEqual(new_user.role, UserRole.ADMIN)

        retrieved = user_repository.get_by_email("qa_lead@secureshare.local")
        self.assertEqual(retrieved.id, new_user.id)

    def test_create_user_duplicate_email_raises_value_error(self):
        with self.assertRaises(ValueError):
            user_repository.create_user(
                email="admin@secureshare.local",  # Already seeded
                password="somepassword123",
                username="another_admin",
            )

    def test_create_user_duplicate_username_raises_value_error(self):
        with self.assertRaises(ValueError):
            user_repository.create_user(
                email="new_unique@secureshare.local",
                password="somepassword123",
                username="admin",  # Already seeded
            )

    def test_update_role(self):
        user = user_repository.get_by_username("user")
        self.assertEqual(user.role, UserRole.USER)

        updated = user_repository.update_role(user.id, UserRole.ADMIN)
        self.assertEqual(updated.role, UserRole.ADMIN)
        self.assertEqual(user_repository.get_by_id(user.id).role, UserRole.ADMIN)


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestAccessAuditLogger(unittest.TestCase):
    """Test audit log emission to backend/logs/app_access.log and interoperability."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_log_path = os.path.join(self.temp_dir, "test_app_access.log")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_log_login_attempt_writes_structured_json(self):
        log_entry = log_login_attempt(
            username="sec_auditor",
            status="SUCCESS",
            ip="192.168.1.55",
            custom_log_path=self.temp_log_path,
        )
        self.assertEqual(log_entry["username"], "sec_auditor")
        self.assertEqual(log_entry["status"], "SUCCESS")
        self.assertEqual(log_entry["status_code"], 200)
        self.assertTrue(os.path.exists(self.temp_log_path))

        with open(self.temp_log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)

        parsed_json = json.loads(lines[0])
        self.assertEqual(parsed_json["user"], "sec_auditor")
        self.assertEqual(parsed_json["ip"], "192.168.1.55")

    def test_log_entry_is_fully_parsed_by_log_analyzer_parser(self):
        """Verify Auth module log format is 100% compliant with Log Analyzer parser."""
        log_login_attempt(
            username="attacker_user",
            status="FAIL",
            ip="203.0.113.99",
            custom_log_path=self.temp_log_path,
        )
        log_login_attempt(
            username="legit_admin",
            status="SUCCESS",
            ip="192.168.1.20",
            custom_log_path=self.temp_log_path,
        )

        parser = LogParser(default_log_path=self.temp_log_path)
        entries = parser.parse_file(self.temp_log_path)

        self.assertEqual(len(entries), 2)
        failed_entry, success_entry = entries[0], entries[1]

        self.assertEqual(failed_entry.user, "attacker_user")
        self.assertEqual(failed_entry.ip, "203.0.113.99")
        self.assertEqual(failed_entry.status_code, 401)
        self.assertTrue(failed_entry.is_failed_login())
        self.assertFalse(failed_entry.is_successful_login())

        self.assertEqual(success_entry.user, "legit_admin")
        self.assertEqual(success_entry.ip, "192.168.1.20")
        self.assertEqual(success_entry.status_code, 200)
        self.assertTrue(success_entry.is_successful_login())
        self.assertFalse(success_entry.is_failed_login())


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestAuthRouterEndpoints(unittest.TestCase):
    """FastAPI TestClient integration tests for Auth & RBAC REST routes."""

    @classmethod
    def setUpClass(cls):
        cls.app = FastAPI(title="Auth Test Server")
        cls.app.include_router(auth_router)
        cls.client = TestClient(cls.app)

    def setUp(self):
        user_repository.clear()

    def test_register_endpoint_success(self):
        payload = {
            "name": "Bob Tester",
            "username": "bob_tester",
            "email": "bob@secureshare.local",
            "password": "Password123!",
            "role": "user",
        }
        res = self.client.post("/auth/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["username"], "bob_tester")
        self.assertEqual(data["email"], "bob@secureshare.local")
        self.assertEqual(data["role"], "user")
        self.assertTrue(data["is_active"])
        self.assertNotIn("password", data)
        self.assertNotIn("hashed_password", data)

    def test_register_duplicate_email_returns_400(self):
        payload = {
            "name": "Admin Clone",
            "username": "admin_clone",
            "email": "admin@secureshare.local",  # Duplicate
            "password": "Password123!",
        }
        res = self.client.post("/auth/register", json=payload)
        self.assertEqual(res.status_code, 400)

    def test_login_success_with_admin_credentials(self):
        payload = {
            "username": "admin",
            "password": "Admin@123456",
        }
        res = self.client.post("/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["username"], "admin")
        self.assertEqual(data["user"]["role"], "admin")

    def test_login_success_with_email(self):
        payload = {
            "email": "user@secureshare.local",
            "password": "User@123456",
        }
        res = self.client.post("/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["username"], "user")

    def test_login_failure_wrong_password_returns_401(self):
        payload = {
            "username": "admin",
            "password": "IncorrectPassword999!",
        }
        res = self.client.post("/auth/login", json=payload)
        self.assertEqual(res.status_code, 401)

    def test_login_failure_nonexistent_user_returns_401(self):
        payload = {
            "username": "non_existent_user_xyz",
            "password": "Password123!",
        }
        res = self.client.post("/auth/login", json=payload)
        self.assertEqual(res.status_code, 401)

    def test_get_me_with_valid_token(self):
        # 1. Login
        login_res = self.client.post("/auth/login", json={"username": "user", "password": "User@123456"})
        token = login_res.json()["access_token"]

        # 2. Get /auth/me
        res = self.client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["username"], "user")

    def test_get_me_without_token_returns_401(self):
        res = self.client.get("/auth/me")
        self.assertEqual(res.status_code, 401)

    def test_rbac_admin_endpoints_permitted_for_admin_denied_for_user(self):
        # Login as user
        user_login = self.client.post("/auth/login", json={"username": "user", "password": "User@123456"})
        user_token = user_login.json()["access_token"]

        # Login as admin
        admin_login = self.client.post("/auth/login", json={"username": "admin", "password": "Admin@123456"})
        admin_token = admin_login.json()["access_token"]

        # Standard user attempting to access /auth/admin/users -> 403 Forbidden
        user_res = self.client.get("/auth/admin/users", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(user_res.status_code, 403)

        # Admin accessing /auth/admin/users -> 200 OK
        admin_res = self.client.get("/auth/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(admin_res.status_code, 200)
        self.assertGreaterEqual(len(admin_res.json()), 2)

        # Standard user attempting /auth/admin/dashboard -> 403 Forbidden
        dash_user = self.client.get("/auth/admin/dashboard", headers={"Authorization": f"Bearer {user_token}"})
        self.assertEqual(dash_user.status_code, 403)

        # Admin accessing /auth/admin/dashboard -> 200 OK
        dash_admin = self.client.get("/auth/admin/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(dash_admin.status_code, 200)
        self.assertEqual(dash_admin.json()["admin_user"], "admin")

    def test_admin_update_user_role(self):
        # Login as admin
        admin_login = self.client.post("/auth/login", json={"username": "admin", "password": "Admin@123456"})
        admin_token = admin_login.json()["access_token"]

        target_user = user_repository.get_by_username("user")
        self.assertEqual(target_user.role, UserRole.USER)

        # Elevate to admin
        res = self.client.put(
            f"/auth/admin/users/{target_user.id}/role",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["role"], "admin")


@unittest.skipIf(not AUTH_DEPS_AVAILABLE, "FastAPI / Pydantic not installed; Node.js test suite covers auth module")
class TestAuthAnalyzerThreatIntegration(unittest.TestCase):
    """End-to-end integration test: Auth logs analyzed by Threat Detection Engine."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_log_path = os.path.join(self.temp_dir, "e2e_access.log")
        self.base_time = datetime(2026, 8, 20, 11, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_brute_force_attack_detected_from_auth_audit_stream(self):
        attacker_ip = "198.51.100.77"
        # Simulate 7 failed login attempts within 35 seconds
        for i in range(7):
            ts = (self.base_time + timedelta(seconds=i * 5)).isoformat().replace("+00:00", "Z")
            log_login_attempt(
                username="admin",
                status="FAIL",
                ip=attacker_ip,
                timestamp=ts,
                custom_log_path=self.temp_log_path,
            )

        parser = LogParser(default_log_path=self.temp_log_path)
        analyzer = LogAnalyzer(parser)
        entries = parser.parse_file(self.temp_log_path)
        self.assertEqual(len(entries), 7)

        alerts = analyzer.analyze(entries)
        brute_alerts = [a for a in alerts if a.alert_type == "BRUTE_FORCE_ATTACK"]
        self.assertEqual(len(brute_alerts), 1)
        self.assertEqual(brute_alerts[0].ip, attacker_ip)
        self.assertEqual(brute_alerts[0].target_user, "admin")
        self.assertEqual(brute_alerts[0].count, 7)

    def test_credential_stuffing_detected_from_auth_audit_stream(self):
        attacker_ip = "203.0.113.150"
        targeted_users = ["root", "admin", "dev_ops", "finance_manager"]
        for i, user in enumerate(targeted_users):
            ts = (self.base_time + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z")
            log_login_attempt(
                username=user,
                status="FAIL",
                ip=attacker_ip,
                timestamp=ts,
                custom_log_path=self.temp_log_path,
            )

        parser = LogParser(default_log_path=self.temp_log_path)
        analyzer = LogAnalyzer(parser)
        entries = parser.parse_file(self.temp_log_path)

        alerts = analyzer.analyze(entries)
        stuffing_alerts = [a for a in alerts if a.alert_type == "CREDENTIAL_STUFFING"]
        self.assertEqual(len(stuffing_alerts), 1)
        self.assertEqual(stuffing_alerts[0].ip, attacker_ip)
        self.assertEqual(stuffing_alerts[0].count, 4)


if __name__ == "__main__":
    unittest.main()
