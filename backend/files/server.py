"""
SecureShare File Sharing Standalone Server
Author: Ahmed
Provides a standalone FastAPI service with CORS support, Swagger/OpenAPI documentation,
and mounts the Secure File Sharing router.
"""

import os
import sys
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure backend package is in python path
_files_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_files_dir)
_root_dir = os.path.dirname(_backend_dir)

for path in [_root_dir, _backend_dir, _files_dir]:
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from backend.files.router import router as files_router, storage_manager
except ImportError:
    try:
        from files.router import router as files_router, storage_manager
    except ImportError:
        from router import router as files_router, storage_manager


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application."""
    app = FastAPI(
        title="SecureShare - Secure File Sharing Service",
        description=(
            "Enterprise-grade Secure File Sharing module by Ahmed for SecureShare Cybersecurity Platform.\n\n"
            "Features:\n"
            "- AES-256-GCM authenticated encryption at rest.\n"
            "- SHA-256 cryptographic hash computation on upload & tamper detection on download.\n"
            "- Multipart file upload, authenticated download, file verification, listing, and secure deletion."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    # Add CORS middleware to support frontend integration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount the file sharing router
    app.include_router(files_router)

    @app.get("/", summary="Root Health & Overview")
    async def root_overview():
        return {
            "service": "SecureShare Secure File Sharing API",
            "author": "Ahmed",
            "status": "operational",
            "features": {
                "encryption": "AES-256-GCM (Authenticated Encryption)",
                "integrity_verification": "SHA-256 Cryptographic Digest",
                "storage_directory": storage_manager.storage_dir
            },
            "endpoints": {
                "upload": "POST /api/files/upload",
                "download": "GET /api/files/download/{file_id}",
                "list": "GET /api/files/list",
                "info": "GET /api/files/info/{file_id}",
                "verify": "GET /api/files/verify/{file_id}",
                "delete": "DELETE /api/files/{file_id}",
                "stats": "GET /api/files/stats",
                "docs": "/docs",
                "redoc": "/redoc"
            }
        }

    @app.get("/health", summary="Health Check")
    async def health_check():
        return {
            "status": "healthy",
            "storage_ok": os.path.exists(storage_manager.storage_dir)
        }

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting SecureShare File Sharing Service on http://127.0.0.1:{port}")
    print(f"[*] Interactive Swagger API documentation: http://127.0.0.1:{port}/docs")
    uvicorn.run("server:app", host=host, port=port, reload=True, app_dir=_files_dir)
