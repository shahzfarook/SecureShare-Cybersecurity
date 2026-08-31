"""
FastAPI Router for Secure File Sharing
Author: Ahmed
Provides upload, download, verification, listing, and deletion REST endpoints with AES-256-GCM encryption
and SHA-256 cryptographic integrity verification.
"""

from typing import Optional, List
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

try:
    from .storage_manager import FileStorageManager, FileNotFoundStorageError, StorageError
    from .crypto import IntegrityVerificationError, DecryptionError, CryptoError
except (ImportError, ValueError):
    from storage_manager import FileStorageManager, FileNotFoundStorageError, StorageError
    from crypto import IntegrityVerificationError, DecryptionError, CryptoError

# Default storage manager instance for the router
storage_manager = FileStorageManager()

router = APIRouter(
    prefix="/api/files",
    tags=["Secure File Sharing"]
)


# --- Pydantic Schemas for API Documentation ---

class FileUploadResponse(BaseModel):
    file_id: str = Field(..., description="Unique UUID identifier for the uploaded file")
    filename: str = Field(..., description="Original sanitized filename")
    content_type: str = Field(..., description="MIME type of the uploaded file")
    file_size: int = Field(..., description="Unencrypted file size in bytes")
    encrypted_size: int = Field(..., description="Ciphertext file size stored on disk in bytes")
    sha256_hash: str = Field(..., description="Cryptographic SHA-256 checksum of the original plaintext")
    encryption_algorithm: str = Field(default="AES-256-GCM", description="Cipher used for encryption at rest")
    uploaded_at: str = Field(..., description="ISO 8601 timestamp of upload")
    description: Optional[str] = Field(None, description="Optional user-provided file description")
    message: str = Field(default="File encrypted with AES-256 and stored successfully.")


class FileInfoResponse(BaseModel):
    file_id: str
    filename: str
    content_type: str
    file_size: int
    encrypted_size: int
    sha256_hash: str
    encryption_algorithm: str
    uploaded_at: str
    description: Optional[str] = None
    status: str


class IntegrityVerificationResponse(BaseModel):
    file_id: str
    filename: Optional[str]
    intact: bool
    stored_sha256: str
    computed_sha256: Optional[str]
    encryption_algorithm: str
    file_size: Optional[int]
    status_message: str
    checked_at: str


class StorageStatsResponse(BaseModel):
    total_files: int
    total_plain_size_bytes: int
    total_encrypted_size_bytes: int
    encryption_standard: str
    integrity_algorithm: str
    storage_path: str


class MessageResponse(BaseModel):
    message: str
    file_id: Optional[str] = None


# --- API Endpoints ---

@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and AES-256 Encrypt File",
    description="Uploads a file, computes its SHA-256 hash, encrypts the payload using AES-256-GCM, and saves it to backend/files/storage/."
)
async def upload_file(
    file: UploadFile = File(..., description="File to upload and encrypt"),
    description: Optional[str] = Form(None, description="Optional description of the file")
):
    """
    1. Reads incoming multipart file bytes.
    2. Calculates SHA-256 cryptographic checksum.
    3. Encrypts payload with AES-256-GCM before writing to backend/files/storage/.
    4. Records file metadata and returns upload confirmation.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid file is required for upload."
        )

    try:
        content = await file.read()
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes). Cannot store empty files."
            )

        metadata = storage_manager.save_file(
            file_content=content,
            original_filename=file.filename,
            content_type=file.content_type or "application/octet-stream",
            description=description or ""
        )

        return FileUploadResponse(
            file_id=metadata["file_id"],
            filename=metadata["filename"],
            content_type=metadata["content_type"],
            file_size=metadata["file_size"],
            encrypted_size=metadata["encrypted_size"],
            sha256_hash=metadata["sha256_hash"],
            encryption_algorithm=metadata.get("encryption_algorithm", "AES-256-GCM"),
            uploaded_at=metadata["uploaded_at"],
            description=metadata.get("description"),
            message="File encrypted with AES-256-GCM and stored successfully with SHA-256 verification hash."
        )
    except HTTPException:
        raise
    except StorageError as se:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Storage error: {str(se)}"
        )
    except CryptoError as ce:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cryptographic failure during upload: {str(ce)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected server error during upload: {str(e)}"
        )


@router.get(
    "/download/{file_id}",
    summary="Download and Verify Decrypted File",
    description="Fetches the AES-256 ciphertext from storage, decrypts it, validates SHA-256 integrity, and returns the verified file stream."
)
async def download_file(file_id: str):
    """
    1. Loads ciphertext from backend/files/storage/{file_id}.enc.
    2. Decrypts payload using AES-256-GCM.
    3. Verifies SHA-256 integrity against metadata hash.
    4. Returns plaintext file with proper download headers.
    """
    try:
        plaintext_bytes, meta = storage_manager.get_file(file_id)
        filename = meta.get("filename", "downloaded_file")
        content_type = meta.get("content_type", "application/octet-stream")
        sha256_hash = meta.get("sha256_hash", "")

        return Response(
            content=plaintext_bytes,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-SHA256-Checksum": sha256_hash,
                "X-Decryption-Status": "verified",
                "X-File-Id": file_id,
                "Content-Length": str(len(plaintext_bytes))
            }
        )
    except FileNotFoundStorageError as fnfe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(fnfe)
        )
    except IntegrityVerificationError as ive:
        # 422 Unprocessable Entity / 409 Conflict due to cryptographic tampering
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Security Alert: {str(ive)}"
        )
    except DecryptionError as de:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Security Alert: Decryption failed. File ciphertext has been altered or corrupted ({str(de)})."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error downloading file: {str(e)}"
        )


@router.get(
    "/list",
    response_model=List[FileInfoResponse],
    summary="List All Stored Files",
    description="Retrieves a list of all active files, their SHA-256 hashes, upload timestamps, and metadata."
)
async def list_files():
    """Returns list of all active encrypted files in storage."""
    try:
        return storage_manager.list_files()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list files: {str(e)}"
        )


@router.get(
    "/info/{file_id}",
    response_model=FileInfoResponse,
    summary="Get File Metadata",
    description="Retrieves metadata for a specific stored file."
)
async def get_file_info(file_id: str):
    """Retrieves file details and SHA-256 checksum."""
    info = storage_manager.get_file_info(file_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' not found."
        )
    return info


@router.get(
    "/verify/{file_id}",
    response_model=IntegrityVerificationResponse,
    summary="Verify File Cryptographic Integrity",
    description="Validates ciphertext and SHA-256 checksum against stored hash without returning full payload."
)
async def verify_file(file_id: str):
    """Performs full AES-256 decryption and SHA-256 hash validation."""
    try:
        return storage_manager.verify_file_integrity(file_id)
    except FileNotFoundStorageError as fnfe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(fnfe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Integrity check error: {str(e)}"
        )


@router.delete(
    "/{file_id}",
    response_model=MessageResponse,
    summary="Delete File",
    description="Permanently deletes ciphertext from backend/files/storage/ and marks record as deleted."
)
async def delete_file(file_id: str):
    """Securely deletes a file and its ciphertext."""
    try:
        storage_manager.delete_file(file_id)
        return MessageResponse(
            message=f"File '{file_id}' and encrypted data permanently deleted.",
            file_id=file_id
        )
    except FileNotFoundStorageError as fnfe:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(fnfe)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete file: {str(e)}"
        )


@router.get(
    "/stats",
    response_model=StorageStatsResponse,
    summary="Storage Statistics",
    description="Returns global statistics on stored encrypted files, total storage usage, and cipher configurations."
)
async def get_storage_stats():
    """Returns storage utilization metrics."""
    return storage_manager.get_storage_stats()
