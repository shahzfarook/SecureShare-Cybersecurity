"""
Authentication Configuration Module
Author: Anuraj
Defines configuration settings, JWT parameters, security defaults, and log file paths.
"""

import os
from pathlib import Path
from typing import List

# Base Paths
AUTH_DIR = Path(__file__).resolve().parent
BACKEND_DIR = AUTH_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
LOGS_DIR = BACKEND_DIR / "logs"
LOG_FILE_PATH = LOGS_DIR / "app_access.log"

# JWT Settings
SECRET_KEY = os.getenv(
    "SECURESHARE_JWT_SECRET",
    "secureshare-super-secret-jwt-key-change-in-production-cybersecurity-2026-xyz"
)
ALGORITHM = os.getenv("SECURESHARE_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Password Policy
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", "6"))

# Default Roles
DEFAULT_ADMIN_ROLE = "admin"
DEFAULT_USER_ROLE = "user"
VALID_ROLES: List[str] = [DEFAULT_ADMIN_ROLE, DEFAULT_USER_ROLE]
