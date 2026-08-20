"""
SecureShare Files Module
Author: Ahmed
Secure File Sharing with AES-256-GCM Encryption and SHA-256 Cryptographic Integrity Verification.
"""

from .crypto import (
    FileEncryptor,
    CryptoError,
    DecryptionError,
    IntegrityVerificationError
)
from .storage_manager import (
    FileStorageManager,
    StorageError,
    FileNotFoundStorageError
)
from .router import (
    router,
    storage_manager,
    FileUploadResponse,
    FileInfoResponse,
    IntegrityVerificationResponse,
    StorageStatsResponse
)
from .server import create_app, app

__all__ = [
    "router",
    "storage_manager",
    "FileEncryptor",
    "FileStorageManager",
    "CryptoError",
    "DecryptionError",
    "IntegrityVerificationError",
    "StorageError",
    "FileNotFoundStorageError",
    "FileUploadResponse",
    "FileInfoResponse",
    "IntegrityVerificationResponse",
    "StorageStatsResponse",
    "create_app",
    "app"
]
