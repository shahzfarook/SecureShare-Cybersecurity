"""
SecureShare File Storage Manager
Author: Ahmed
Handles AES-256 encrypted file persistence, metadata tracking, directory management,
and cryptographic integrity validation for files stored in backend/files/storage/.
"""

import os
import json
import uuid
import threading
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any

from .crypto import FileEncryptor, CryptoError, IntegrityVerificationError, DecryptionError


class StorageError(Exception):
    """Base exception for file storage operations."""
    pass


class FileNotFoundStorageError(StorageError):
    """Raised when a requested file or its metadata does not exist."""
    pass


class FileStorageManager:
    """
    Manages local encrypted storage under backend/files/storage/.
    All stored files are encrypted using AES-256-GCM prior to being written to disk.
    Integrity is guaranteed via SHA-256 cryptographic hashes.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize the storage manager.
        Defaults to backend/files/storage/ directory.
        """
        if storage_dir is None:
            # Default to backend/files/storage/
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.storage_dir = os.path.join(base_dir, "storage")
        else:
            self.storage_dir = os.path.abspath(storage_dir)

        self.metadata_file = os.path.join(self.storage_dir, "metadata.json")
        self.key_file = os.path.join(self.storage_dir, ".master_key")
        self._lock = threading.RLock()

        # Ensure storage directory exists
        os.makedirs(self.storage_dir, exist_ok=True)

        # Initialize or load the master encryption key
        master_key = self._load_or_create_master_key()
        self.encryptor = FileEncryptor(master_key=master_key)

        # Ensure metadata file exists
        self._ensure_metadata_file()

    def _load_or_create_master_key(self) -> bytes:
        """
        Loads master key from environment variable SECURESHARE_SECRET_KEY,
        or from key_file in storage directory, or generates a new one.
        """
        env_key = os.environ.get("SECURESHARE_SECRET_KEY")
        if env_key:
            try:
                # Try hex decode
                if len(env_key) == 64:
                    return bytes.fromhex(env_key)
                key_bytes = env_key.encode("utf-8")
                if len(key_bytes) == 32:
                    return key_bytes
            except Exception:
                pass

        # Check existing key file
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    key_data = f.read().strip()
                if len(key_data) == 64:  # Hex-encoded
                    return bytes.fromhex(key_data.decode("utf-8"))
                elif len(key_data) == 32:  # Raw bytes
                    return key_data
            except Exception:
                pass

        # Generate new master key and persist
        new_key = FileEncryptor.generate_key()
        try:
            with open(self.key_file, "w", encoding="utf-8") as f:
                f.write(new_key.hex())
        except Exception:
            pass
        return new_key

    def _ensure_metadata_file(self) -> None:
        """Initializes empty metadata store if not present."""
        with self._lock:
            if not os.path.exists(self.metadata_file):
                with open(self.metadata_file, "w", encoding="utf-8") as f:
                    json.dump({}, f, indent=2)

    def _read_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Reads metadata JSON store thread-safely."""
        with self._lock:
            if not os.path.exists(self.metadata_file):
                return {}
            try:
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}

    def _write_metadata(self, metadata: Dict[str, Dict[str, Any]]) -> None:
        """Writes metadata JSON store atomically."""
        with self._lock:
            temp_path = self.metadata_file + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            os.replace(temp_path, self.metadata_file)

    def _get_encrypted_filepath(self, file_id: str) -> str:
        """Returns the full path to the encrypted file on disk."""
        return os.path.join(self.storage_dir, f"{file_id}.enc")

    def _sanitize_filename(self, filename: str) -> str:
        """Strips path traversal elements and unsafe characters from filenames."""
        cleaned = os.path.basename(filename)
        cleaned = "".join(c for c in cleaned if c.isalnum() or c in "._- ()[]+")
        return cleaned or "unnamed_file"

    def save_file(
        self,
        file_content: bytes,
        original_filename: str,
        content_type: str = "application/octet-stream",
        description: str = ""
    ) -> Dict[str, Any]:
        """
        Encrypts file contents using AES-256-GCM, computes SHA-256 hash,
        saves ciphertext to backend/files/storage/{file_id}.enc, and records metadata.
        
        Returns:
            Dict containing file metadata and cryptographic hashes.
        """
        if not file_content:
            raise StorageError("Cannot save empty file.")

        sanitized_name = self._sanitize_filename(original_filename)
        file_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # 1. Encrypt with AES-256-GCM and compute original SHA-256
        encrypted_bytes, sha256_hash = self.encryptor.encrypt(plaintext=file_content)

        # 2. Write ciphertext to disk
        enc_path = self._get_encrypted_filepath(file_id)
        with open(enc_path, "wb") as f:
            f.write(encrypted_bytes)

        # 3. Create metadata record
        meta_entry = {
            "file_id": file_id,
            "filename": sanitized_name,
            "content_type": content_type or "application/octet-stream",
            "file_size": len(file_content),
            "encrypted_size": len(encrypted_bytes),
            "sha256_hash": sha256_hash,
            "encryption_algorithm": "AES-256-GCM",
            "uploaded_at": timestamp,
            "description": description or "",
            "status": "active"
        }

        # 4. Atomically persist metadata
        with self._lock:
            all_meta = self._read_metadata()
            all_meta[file_id] = meta_entry
            self._write_metadata(all_meta)

        return meta_entry

    def get_file(self, file_id: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Retrieves encrypted file from storage, decrypts with AES-256-GCM,
        and verifies SHA-256 cryptographic integrity.
        
        Returns:
            Tuple of (decrypted_plaintext_bytes, metadata_dict)
            
        Raises:
            FileNotFoundStorageError: If file or metadata does not exist.
            IntegrityVerificationError: If SHA-256 integrity check fails.
            DecryptionError: If ciphertext authentication tag fails.
        """
        all_meta = self._read_metadata()
        meta = all_meta.get(file_id)

        if not meta or meta.get("status") != "active":
            raise FileNotFoundStorageError(f"File with ID '{file_id}' was not found.")

        enc_path = self._get_encrypted_filepath(file_id)
        if not os.path.exists(enc_path):
            raise FileNotFoundStorageError(f"Encrypted file on disk for ID '{file_id}' is missing.")

        # Read encrypted payload
        with open(enc_path, "rb") as f:
            encrypted_payload = f.read()

        # Decrypt and verify SHA-256 integrity
        expected_hash = meta.get("sha256_hash")
        plaintext, verified = self.encryptor.decrypt(
            encrypted_payload=encrypted_payload,
            expected_sha256=expected_hash
        )

        return plaintext, meta

    def verify_file_integrity(self, file_id: str) -> Dict[str, Any]:
        """
        Verifies SHA-256 cryptographic integrity of a stored encrypted file.
        
        Returns:
            Dict with verification results (is_intact, stored_hash, computed_hash, etc.)
        """
        all_meta = self._read_metadata()
        meta = all_meta.get(file_id)

        if not meta or meta.get("status") != "active":
            raise FileNotFoundStorageError(f"File with ID '{file_id}' was not found.")

        enc_path = self._get_encrypted_filepath(file_id)
        if not os.path.exists(enc_path):
            raise FileNotFoundStorageError(f"Encrypted file on disk for ID '{file_id}' is missing.")

        with open(enc_path, "rb") as f:
            encrypted_payload = f.read()

        expected_hash = meta.get("sha256_hash", "")
        try:
            plaintext, _ = self.encryptor.decrypt(
                encrypted_payload=encrypted_payload,
                expected_sha256=expected_hash
            )
            computed_hash = FileEncryptor.compute_sha256(plaintext)
            intact = (computed_hash.lower() == expected_hash.lower())
            status_message = "Integrity verified: SHA-256 hash matches original upload."
        except DecryptionError as de:
            intact = False
            computed_hash = None
            status_message = f"Decryption failed: Ciphertext altered or corrupted ({str(de)})"
        except IntegrityVerificationError as ie:
            intact = False
            computed_hash = str(ie)
            status_message = f"Integrity check failed: {str(ie)}"

        return {
            "file_id": file_id,
            "filename": meta.get("filename"),
            "intact": intact,
            "stored_sha256": expected_hash,
            "computed_sha256": computed_hash,
            "encryption_algorithm": meta.get("encryption_algorithm", "AES-256-GCM"),
            "file_size": meta.get("file_size"),
            "status_message": status_message,
            "checked_at": datetime.now(timezone.utc).isoformat()
        }

    def list_files(self) -> List[Dict[str, Any]]:
        """Returns a list of all active files and their metadata."""
        all_meta = self._read_metadata()
        active_files = [
            meta for meta in all_meta.values()
            if meta.get("status") == "active"
        ]
        # Sort descending by upload timestamp
        active_files.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
        return active_files

    def get_file_info(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Returns metadata for a specific file ID if active."""
        all_meta = self._read_metadata()
        meta = all_meta.get(file_id)
        if meta and meta.get("status") == "active":
            return meta
        return None

    def delete_file(self, file_id: str) -> bool:
        """
        Securely deletes the encrypted file from storage and updates metadata.
        """
        all_meta = self._read_metadata()
        meta = all_meta.get(file_id)
        if not meta:
            raise FileNotFoundStorageError(f"File with ID '{file_id}' was not found.")

        enc_path = self._get_encrypted_filepath(file_id)
        if os.path.exists(enc_path):
            try:
                os.remove(enc_path)
            except OSError as e:
                raise StorageError(f"Failed to remove file from disk: {str(e)}") from e

        # Mark status as deleted in metadata
        with self._lock:
            all_meta[file_id]["status"] = "deleted"
            all_meta[file_id]["deleted_at"] = datetime.now(timezone.utc).isoformat()
            self._write_metadata(all_meta)

        return True

    def get_storage_stats(self) -> Dict[str, Any]:
        """Returns summary statistics for the secure file storage system."""
        active_files = self.list_files()
        total_plain_bytes = sum(f.get("file_size", 0) for f in active_files)
        total_encrypted_bytes = sum(f.get("encrypted_size", 0) for f in active_files)

        return {
            "total_files": len(active_files),
            "total_plain_size_bytes": total_plain_bytes,
            "total_encrypted_size_bytes": total_encrypted_bytes,
            "encryption_standard": "AES-256-GCM (Authenticated Encryption)",
            "integrity_algorithm": "SHA-256",
            "storage_path": self.storage_dir
        }
