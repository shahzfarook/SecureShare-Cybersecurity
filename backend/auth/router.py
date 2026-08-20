"""
Authentication & RBAC REST API Router
Author: Anuraj
FastAPI APIRouter exposing endpoints for registration, login, token refresh, and RBAC-protected resources.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, status

try:
    from .models import (
        UserRole,
        UserRegisterRequest,
        UserLoginRequest,
        UserResponse,
        TokenResponse,
        RoleUpdateRequest,
    )
    from .security import (
        verify_password,
        create_access_token,
    )
    from .logger import log_login_attempt
    from .storage import user_repository, UserRecord
    from .dependencies import (
        get_current_user,
        require_admin,
        require_user,
        get_client_ip,
    )
    from .config import ACCESS_TOKEN_EXPIRE_MINUTES
except (ImportError, ValueError):
    from models import (
        UserRole,
        UserRegisterRequest,
        UserLoginRequest,
        UserResponse,
        TokenResponse,
        RoleUpdateRequest,
    )
    from security import (
        verify_password,
        create_access_token,
    )
    from logger import log_login_attempt
    from storage import user_repository, UserRecord
    from dependencies import (
        get_current_user,
        require_admin,
        require_user,
        get_client_ip,
    )
    from config import ACCESS_TOKEN_EXPIRE_MINUTES

# Main APIRouter exported for inclusion in top-level server
auth_router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])
router = auth_router  # Alias for standard naming


@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(
    payload: UserRegisterRequest,
    request: Request,
):
    """
    Register a new user account with bcrypt password hashing.
    """
    client_ip = get_client_ip(request)
    try:
        user = user_repository.create_user(
            email=payload.email,
            password=payload.password,
            username=payload.username or payload.name,
            name=payload.name,
            role=payload.role or UserRole.USER,
        )
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            name=user.name,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and issue JWT token",
)
async def login(
    payload: UserLoginRequest,
    request: Request,
):
    """
    Authenticate user credentials, log attempt to backend/logs/app_access.log,
    and return signed JWT access token.
    """
    client_ip = get_client_ip(request)
    identifier = payload.email or payload.username

    if not identifier:
        log_login_attempt(
            username="anonymous",
            status="FAIL",
            ip=client_ip,
            status_code=400,
            message="Login failed: Missing email or username identifier",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either email or username must be provided.",
        )

    user = user_repository.get_by_identifier(identifier)

    # Verify user exists and password hash matches
    if not user or not verify_password(payload.password, user.hashed_password):
        log_login_attempt(
            username=identifier,
            status="FAIL",
            ip=client_ip,
            status_code=401,
            message=f"Login failed: Invalid credentials for identifier '{identifier}'",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Check your email/username and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        log_login_attempt(
            username=identifier,
            status="FAIL",
            ip=client_ip,
            status_code=403,
            message=f"Login failed: Account '{identifier}' is deactivated",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact support.",
        )

    # Log successful login attempt
    log_login_attempt(
        username=user.username,
        status="SUCCESS",
        ip=client_ip,
        status_code=200,
        message=f"Login successful for user: {user.username} ({user.email})",
    )

    # Generate JWT access token with user claims & role
    token_claims = {
        "sub": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role.value if isinstance(user.role, UserRole) else str(user.role),
    }
    access_token = create_access_token(token_claims)

    user_response = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        name=user.name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_response,
    )


@auth_router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
async def get_me(
    current_user: UserRecord = Depends(get_current_user),
):
    """Return the profile of the currently authenticated user."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        name=current_user.name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


# ==========================================
# RBAC: Admin-Only Endpoints
# ==========================================

@auth_router.get(
    "/admin/users",
    response_model=List[UserResponse],
    summary="[Admin] List all registered users",
)
async def admin_list_users(
    admin: UserRecord = Depends(require_admin),
):
    """Admin-only endpoint to list all registered users."""
    users = user_repository.list_all()
    return [
        UserResponse(
            id=u.id,
            username=u.username,
            email=u.email,
            name=u.name,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
        )
        for u in users
    ]


@auth_router.get(
    "/admin/dashboard",
    summary="[Admin] Get administrative summary metrics",
)
async def admin_dashboard(
    admin: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Admin-only endpoint providing security and user statistics."""
    users = user_repository.list_all()
    admin_count = sum(1 for u in users if u.role == UserRole.ADMIN)
    user_count = sum(1 for u in users if u.role == UserRole.USER)
    active_count = sum(1 for u in users if u.is_active)

    return {
        "status": "authorized",
        "admin_user": admin.username,
        "total_users": len(users),
        "admin_count": admin_count,
        "standard_user_count": user_count,
        "active_users": active_count,
    }


@auth_router.put(
    "/admin/users/{user_id}/role",
    response_model=UserResponse,
    summary="[Admin] Modify user role",
)
async def admin_update_user_role(
    user_id: str,
    payload: RoleUpdateRequest,
    admin: UserRecord = Depends(require_admin),
):
    """Admin-only endpoint to elevate or downgrade user roles."""
    updated = user_repository.update_role(user_id, payload.role)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' was not found.",
        )
    return UserResponse(
        id=updated.id,
        username=updated.username,
        email=updated.email,
        name=updated.name,
        role=updated.role,
        is_active=updated.is_active,
        created_at=updated.created_at,
    )


# ==========================================
# RBAC: Standard User Endpoints
# ==========================================

@auth_router.get(
    "/user/profile",
    summary="[User] Access user profile data",
)
async def user_profile(
    current_user: UserRecord = Depends(require_user),
) -> Dict[str, Any]:
    """Standard user accessible endpoint."""
    return {
        "message": f"Welcome back, {current_user.name or current_user.username}!",
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role.value if isinstance(current_user.role, UserRole) else str(current_user.role),
    }
