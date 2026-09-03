"""
Unit and Integration Test Suite for SecureShare Secure File Sharing Module
Author: Ahmed / QA Team
Run with: pytest backend/files/ or python3 -m unittest backend/files/test_files.py
"""

from datetime import datetime, timezone
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None
    TestClient = None
    FASTAPI_AVAILABLE = False

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
    from backend.files.crypto import (
        FileEncryptor,
        CryptoError,
        DecryptionError,
        IntegrityVerificationError,
    )
    from backend.files.storage_manager import (
        FileStorageManager,
        StorageError,
        FileNotFoundStorageError,
    )
    from backend.files.otp_manager import DownloadOTPManager, download_otp_manager
    if FASTAPI_AVAILABLE:
        from backend.files.router import (
            router as files_router,
            storage_manager,
        )
    else:
        files_router = None
        storage_manager = None
except (ImportError, ValueError):
    from crypto import (
        FileEncryptor,
        CryptoError,
        DecryptionError,
        IntegrityVerificationError,
    )
    from storage_manager import (
        FileStorageManager,
        StorageError,
        FileNotFoundStorageError,
    )
    from otp_manager import DownloadOTPManager, download_otp_manager
    files_router = None
    storage_manager = None


class TestFileEncryptor(unittest.TestCase):
    """Test cryptographic functions, AES-256-GCM encryption, and SHA-256 verification."""

    def setUp(self):
        self.encryptor = FileEncryptor()

    def test_key_generation_length(self):
        key = FileEncryptor.generate_key()
        self.assertEqual(len(key), 32)  # 256 bits

    def test_sha256_computation_and_verification(self):
        data = b"Confidential Cybersecurity Log and Threat Report 2026"
        expected_hash = FileEncryptor.compute_sha256(data)
        self.assertEqual(len(expected_hash), 64)
        self.assertTrue(FileEncryptor.verify_sha256(data, expected_hash))
        self.assertFalse(FileEncryptor.verify_sha256(b"Tampered Data", expected_hash))

    def test_aes256_gcm_encrypt_decrypt_roundtrip(self):
        plaintext = b"Highly sensitive proprietary source code and encryption keys."
        ciphertext, sha256_hash = self.encryptor.encrypt(plaintext)

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(sha256_hash, FileEncryptor.compute_sha256(plaintext))

        decrypted, verified = self.encryptor.decrypt(ciphertext, expected_sha256=sha256_hash)
        self.assertEqual(decrypted, plaintext)
        self.assertTrue(verified)

    def test_decrypt_with_tampered_ciphertext_raises_decryption_error(self):
        plaintext = b"Authentic payload"
        ciphertext, sha256_hash = self.encryptor.encrypt(plaintext)

        # Corrupt the ciphertext bytes
        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0xFF
        corrupted_bytes = bytes(corrupted)

        with self.assertRaises(DecryptionError):
            self.encryptor.decrypt(corrupted_bytes, expected_sha256=sha256_hash)

    def test_decrypt_with_mismatched_sha256_raises_integrity_verification_error(self):
        plaintext = b"Legitimate document"
        ciphertext, _ = self.encryptor.encrypt(plaintext)
        wrong_hash = "0" * 64

        with self.assertRaises(IntegrityVerificationError):
            self.encryptor.decrypt(ciphertext, expected_sha256=wrong_hash)


class TestFileStorageManager(unittest.TestCase):
    """Test encrypted file persistence, metadata management, and retrieval."""

    def setUp(self):
        self.temp_storage_dir = tempfile.mkdtemp()
        self.manager = FileStorageManager(storage_dir=self.temp_storage_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_storage_dir, ignore_errors=True)

    def test_store_and_retrieve_file(self):
        filename = "incident_report.pdf"
        content = b"%PDF-1.4 Mock cybersecurity audit report content"
        content_type = "application/pdf"

        meta = self.manager.save_file(
            original_filename=filename,
            file_content=content,
            content_type=content_type,
            description="Q3 Security Audit",
        )

        self.assertIn("file_id", meta)
        self.assertEqual(meta["filename"], filename)
        self.assertEqual(meta["file_size"], len(content))
        self.assertEqual(meta["sha256_hash"], FileEncryptor.compute_sha256(content))

        # Retrieve file
        retrieved_bytes, retrieved_meta = self.manager.get_file(meta["file_id"])
        self.assertEqual(retrieved_bytes, content)
        self.assertEqual(retrieved_meta["file_id"], meta["file_id"])

    def test_retrieve_nonexistent_file_raises_not_found(self):
        with self.assertRaises(FileNotFoundStorageError):
            self.manager.get_file("non-existent-uuid-12345")

    def test_list_and_delete_file(self):
        meta = self.manager.save_file(
            original_filename="test.txt",
            file_content=b"Hello world",
            content_type="text/plain",
        )
        file_list = self.manager.list_files()
        self.assertEqual(len(file_list), 1)
        self.assertEqual(file_list[0]["file_id"], meta["file_id"])

        # Delete
        deleted = self.manager.delete_file(meta["file_id"])
        self.assertTrue(deleted)
        self.assertEqual(len(self.manager.list_files()), 0)

    def test_storage_statistics(self):
        self.manager.save_file(original_filename="file1.bin", file_content=b"1234567890", content_type="application/octet-stream")
        self.manager.save_file(original_filename="file2.bin", file_content=b"abcdefghij", content_type="application/octet-stream")

        stats = self.manager.get_storage_stats()
        self.assertEqual(stats["total_files"], 2)
class TestDownloadOTPManager(unittest.TestCase):
    """Unit tests for 2FA email OTP generation, 5-minute expiration, and verification."""

    def setUp(self):
        self.otp_manager = DownloadOTPManager()
        self.file_id = "test-file-uuid-12345"
        self.email = "operator@secureshare.local"
        self.filename = "secret_audit.pdf"

    def test_otp_generation_and_expiry(self):
        res = self.otp_manager.generate_otp(self.file_id, self.email, self.filename)
        self.assertEqual(res["file_id"], self.file_id)
        self.assertEqual(len(res["dev_otp"]), 6)
        self.assertTrue(res["dev_otp"].isdigit())
        self.assertEqual(res["expires_in_seconds"], 300)
        self.assertIn("@", res["recipient_email"])

        active = self.otp_manager.get_active_otp(self.file_id)
        self.assertIsNotNone(active)
        self.assertEqual(active["file_id"], self.file_id)
        self.assertGreater(active["expires_in_seconds"], 0)

    def test_otp_valid_verification_and_consumption(self):
        res = self.otp_manager.generate_otp(self.file_id, self.email, self.filename)
        code = res["dev_otp"]

        is_valid, msg = self.otp_manager.verify_otp(self.file_id, code)
        self.assertTrue(is_valid)
        self.assertIn("verified", msg.lower())

        # Single-use: Subsequent verification of same code must fail
        is_valid_again, msg_again = self.otp_manager.verify_otp(self.file_id, code)
        self.assertFalse(is_valid_again)
        self.assertIn("no active download otp found", msg_again.lower())

    def test_otp_wrong_code_rejection_and_lockout(self):
        self.otp_manager.generate_otp(self.file_id, self.email, self.filename)

        # Attempt 1
        is_valid_1, msg_1 = self.otp_manager.verify_otp(self.file_id, "000000")
        self.assertFalse(is_valid_1)
        self.assertIn("2 attempt(s) remaining", msg_1)

        # Attempt 2
        is_valid_2, msg_2 = self.otp_manager.verify_otp(self.file_id, "111111")
        self.assertFalse(is_valid_2)
        self.assertIn("1 attempt(s) remaining", msg_2)

        # Attempt 3 -> Lockout / Invalidated
        is_valid_3, msg_3 = self.otp_manager.verify_otp(self.file_id, "222222")
        self.assertFalse(is_valid_3)
        self.assertIn("exceeded", msg_3.lower())

        # Further attempts fail completely
        is_valid_4, msg_4 = self.otp_manager.verify_otp(self.file_id, "333333")
        self.assertFalse(is_valid_4)

    def test_email_masking(self):
        self.assertEqual(DownloadOTPManager.mask_email("admin@secureshare.local"), "a***n@secureshare.local")
        self.assertEqual(DownloadOTPManager.mask_email("me@example.com"), "m***@example.com")
        self.assertEqual(DownloadOTPManager.mask_email("invalid"), "u***@secureshare.local")


@unittest.skipIf(not FASTAPI_AVAILABLE, "FastAPI / TestClient not installed in environment")
class TestFilesRouterEndpoints(unittest.TestCase):
    """FastAPI TestClient integration tests for file sharing endpoints."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.test_manager = FileStorageManager(storage_dir=cls.temp_dir)
        import backend.files.router as r_mod
        r_mod.storage_manager = cls.test_manager

        cls.app = FastAPI(title="Files Test Server")
        cls.app.include_router(files_router)
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_upload_file_endpoint(self):
        file_content = b"Secure payload to be encrypted at rest with AES-256-GCM."
        files = {"file": ("test_document.txt", io.BytesIO(file_content), "text/plain")}
        data = {"description": "End-to-end upload test"}

        res = self.client.post("/api/files/upload", files=files, data=data)
        self.assertEqual(res.status_code, 201)
        resp_data = res.json()

        self.assertIn("file_id", resp_data)
        self.assertEqual(resp_data["filename"], "test_document.txt")
        self.assertEqual(resp_data["file_size"], len(file_content))
        self.assertEqual(resp_data["encryption_algorithm"], "AES-256-GCM")

        file_id = resp_data["file_id"]

        info_res = self.client.get(f"/api/files/info/{file_id}")
        self.assertEqual(info_res.status_code, 200)
        self.assertEqual(info_res.json()["filename"], "test_document.txt")

        verify_res = self.client.get(f"/api/files/verify/{file_id}")
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.json()["intact"])

        download_res = self.client.get(f"/api/files/download/{file_id}")
        self.assertEqual(download_res.status_code, 200)
        self.assertEqual(download_res.content, file_content)

        list_res = self.client.get("/api/files/list")
        self.assertEqual(list_res.status_code, 200)
        self.assertGreaterEqual(len(list_res.json()), 1)

        stats_res = self.client.get("/api/files/stats")
        self.assertEqual(stats_res.status_code, 200)
        self.assertGreaterEqual(stats_res.json()["total_files"], 1)

        del_res = self.client.delete(f"/api/files/{file_id}")
        self.assertEqual(del_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
