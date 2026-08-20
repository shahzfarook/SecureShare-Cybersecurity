"""
SecureShare Cryptography Engine
Author: Ahmed
Provides AES-256-GCM encryption/decryption, key management, and SHA-256 cryptographic hash computation
and integrity verification.
"""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails (e.g. invalid key or corrupted ciphertext/tag)."""
    pass


class IntegrityVerificationError(CryptoError):
    """Raised when decrypted payload fails SHA-256 integrity verification."""
    pass


class FileEncryptor:
    """
    AES-256-GCM file encryption and SHA-256 integrity verification engine.
    
    Security specs:
    - Cipher: AES-256-GCM (Galois/Counter Mode) authenticated encryption
    - Key Size: 256 bits (32 bytes)
    - Nonce/IV: 96 bits (12 bytes) cryptographically random per encryption
    - Integrity: SHA-256 cryptographic checksum verified with constant-time comparison
    """

    NONCE_SIZE_BYTES = 12  # Standard 96-bit nonce for AES-GCM
    KEY_SIZE_BYTES = 32    # 256-bit key

    def __init__(self, master_key: Optional[bytes] = None):
        """
        Initialize the encryptor with a 256-bit (32-byte) master key.
        If no key is provided, a secure random key is generated.
        """
        if master_key is not None:
            if len(master_key) != self.KEY_SIZE_BYTES:
                raise ValueError(
                    f"Master key must be exactly {self.KEY_SIZE_BYTES} bytes (256 bits). "
                    f"Provided key length: {len(master_key)} bytes."
                )
            self._master_key = master_key
        else:
            self._master_key = self.generate_key()

    @property
    def master_key(self) -> bytes:
        """Returns the current master encryption key."""
        return self._master_key

    @classmethod
    def generate_key(cls) -> bytes:
        """Generates a cryptographically secure 256-bit (32-byte) key."""
        return secrets.token_bytes(cls.KEY_SIZE_BYTES)

    @classmethod
    def compute_sha256(cls, data: bytes) -> str:
        """
        Computes the SHA-256 cryptographic hash of the input bytes.
        Returns a 64-character lowercase hexadecimal digest.
        """
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    @classmethod
    def verify_sha256(cls, data: bytes, expected_hash: str) -> bool:
        """
        Verifies that data matches expected SHA-256 hash using constant-time comparison
        to prevent timing attacks.
        """
        computed_hash = cls.compute_sha256(data)
        return hmac.compare_digest(computed_hash.lower(), expected_hash.lower())

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
        key: Optional[bytes] = None
    ) -> Tuple[bytes, str]:
        """
        Encrypts plaintext bytes using AES-256-GCM.
        
        Process:
        1. Computes SHA-256 checksum of original plaintext.
        2. Generates a fresh 12-byte random nonce.
        3. Encrypts and authenticates using AES-GCM (ciphertext includes 16-byte auth tag).
        4. Packages as [12-byte Nonce] + [Ciphertext + Tag].
        
        Returns:
            Tuple of (encrypted_payload_bytes, sha256_hash_of_plaintext)
        """
        active_key = key or self._master_key
        if len(active_key) != self.KEY_SIZE_BYTES:
            raise CryptoError(f"Encryption key must be {self.KEY_SIZE_BYTES} bytes")

        # 1. Compute SHA-256 hash of original plaintext before encryption
        sha256_hash = self.compute_sha256(plaintext)

        # 2. Generate random 12-byte nonce
        nonce = secrets.token_bytes(self.NONCE_SIZE_BYTES)

        # 3. Encrypt with AES-256-GCM
        try:
            aesgcm = AESGCM(active_key)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        except Exception as e:
            raise CryptoError(f"AES-256-GCM encryption failed: {str(e)}") from e

        # 4. Pack: Nonce + Ciphertext (which includes GCM tag at the end)
        encrypted_payload = nonce + ciphertext_with_tag
        return encrypted_payload, sha256_hash

    def decrypt(
        self,
        encrypted_payload: bytes,
        expected_sha256: Optional[str] = None,
        associated_data: Optional[bytes] = None,
        key: Optional[bytes] = None
    ) -> Tuple[bytes, bool]:
        """
        Decrypts an encrypted payload using AES-256-GCM and verifies SHA-256 integrity.
        
        Process:
        1. Extracts 12-byte nonce and ciphertext.
        2. Decrypts and authenticates with AES-256-GCM.
        3. Computes SHA-256 of decrypted plaintext and verifies against expected_sha256.
        
        Returns:
            Tuple of (decrypted_plaintext_bytes, integrity_verified: bool)
            
        Raises:
            DecryptionError: If ciphertext is corrupt, key is invalid, or GCM tag check fails.
            IntegrityVerificationError: If SHA-256 hash does not match expected_sha256.
        """
        active_key = key or self._master_key
        if len(active_key) != self.KEY_SIZE_BYTES:
            raise CryptoError(f"Decryption key must be {self.KEY_SIZE_BYTES} bytes")

        if len(encrypted_payload) < self.NONCE_SIZE_BYTES + 16:  # Nonce + minimum GCM tag (16 bytes)
            raise DecryptionError("Encrypted payload is too short to contain a valid Nonce and GCM tag.")

        # 1. Extract nonce and ciphertext
        nonce = encrypted_payload[:self.NONCE_SIZE_BYTES]
        ciphertext_with_tag = encrypted_payload[self.NONCE_SIZE_BYTES:]

        # 2. Decrypt with AES-256-GCM
        try:
            aesgcm = AESGCM(active_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        except Exception as e:
            raise DecryptionError(
                f"AES-256-GCM decryption failed (ciphertext may have been tampered with or key is incorrect): {str(e)}"
            ) from e

        # 3. Verify SHA-256 integrity
        integrity_verified = True
        if expected_sha256:
            if not self.verify_sha256(plaintext, expected_sha256):
                computed = self.compute_sha256(plaintext)
                raise IntegrityVerificationError(
                    f"Cryptographic integrity verification failed! "
                    f"Expected SHA-256: {expected_sha256}, Computed SHA-256: {computed}"
                )

        return plaintext, integrity_verified
