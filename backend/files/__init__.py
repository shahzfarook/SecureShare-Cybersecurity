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

try:
    from .router import (
        router,
        storage_manager,
        FileUploadResponse,
        FileInfoResponse,
        IntegrityVerificationResponse,
        StorageStatsResponse
    )
    from .server import create_app, app
except ImportError:
    router = None
    storage_manager = None
    FileUploadResponse = None
    FileInfoResponse = None
    IntegrityVerificationResponse = None
    StorageStatsResponse = None
    create_app = None
    app = None

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
