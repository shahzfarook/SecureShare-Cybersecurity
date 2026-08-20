"""
SecureShare Authentication & Access Control Module
Author: Anuraj

Provides:
- User registration, login, and JWT authentication with bcrypt password hashing
- Role-Based Access Control (Admin vs Standard User)
- Audit log helper recording attempts into backend/logs/app_access.log
- Exportable FastAPI APIRouter (auth_router / router)
"""

from .config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    LOG_FILE_PATH,
)
from .models import (
    UserRole,
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
    TokenPayload,
    RoleUpdateRequest,
    LoginAttemptLog,
)
from .security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from .logger import (
    log_login_attempt,
)
from .storage import (
    user_repository,
    UserRepository,
    UserRecord,
)
from .dependencies import (
    get_current_user,
    require_admin,
    require_user,
    RoleChecker,
    get_client_ip,
)
from .router import (
    auth_router,
    router,
)

__all__ = [
    # Router
    "auth_router",
    "router",
    # Config
    "SECRET_KEY",
    "ALGORITHM",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "LOG_FILE_PATH",
    # Models & Roles
    "UserRole",
    "UserRegisterRequest",
    "UserLoginRequest",
    "UserResponse",
    "TokenResponse",
    "TokenPayload",
    "RoleUpdateRequest",
    "LoginAttemptLog",
    # Security
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    # Logger
    "log_login_attempt",
    # Storage
    "user_repository",
    "UserRepository",
    "UserRecord",
    # Dependencies & RBAC
    "get_current_user",
    "require_admin",
    "require_user",
    "RoleChecker",
    "get_client_ip",
]
