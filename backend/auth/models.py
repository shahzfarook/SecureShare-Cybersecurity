"""
Authentication & RBAC Data Models
Author: Anuraj
Defines Pydantic schemas for user registration, authentication, token payloads, and RBAC roles.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, ConfigDict


class UserRole(str, Enum):
    """Supported user roles for Role-Based Access Control."""
    ADMIN = "admin"
    USER = "user"


EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class UserRegisterRequest(BaseModel):
    """Schema for user registration request."""
    name: Optional[str] = Field(default=None, description="Full name or display name")
    username: Optional[str] = Field(default=None, description="Unique username")
    email: str = Field(..., description="Unique email address")
    password: str = Field(..., min_length=6, description="Plaintext password (min 6 characters)")
    role: Optional[UserRole] = Field(default=UserRole.USER, description="Assigned role")

    @field_validator("email", mode="before")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("Email must be a non-empty string.")
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError(f"Invalid email address format: {v}")
        return cleaned

    @field_validator("username", mode="before")
    @classmethod
    def set_default_username(cls, v: Optional[str]) -> str:
        if v and isinstance(v, str) and v.strip():
            return v.strip().lower()
        return ""


class UserLoginRequest(BaseModel):
    """Schema for user login request."""
    email: Optional[str] = Field(default=None, description="User email address")
    username: Optional[str] = Field(default=None, description="Username (alternative to email)")
    password: str = Field(..., description="Plaintext password")

    @field_validator("email", "username", mode="before")
    @classmethod
    def strip_and_lower(cls, v: Optional[str]) -> Optional[str]:
        return v.strip().lower() if v and isinstance(v, str) else v


class UserResponse(BaseModel):
    """Public user response schema (excluding sensitive attributes)."""
    id: str
    username: str
    email: str
    name: Optional[str] = None
    role: UserRole
    is_active: bool = True
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    """OAuth2 / JWT Token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenPayload(BaseModel):
    """Decoded JWT payload structure."""
    sub: str  # User ID
    email: str
    username: str
    role: str
    exp: int
    iat: int


class RoleUpdateRequest(BaseModel):
    """Schema for administrative role modification."""
    role: UserRole


class LoginAttemptLog(BaseModel):
    """Structured audit log model for login events."""
    Timestamp: str = Field(..., description="ISO formatted timestamp")
    Username: str = Field(..., description="Username or email attempted")
    Status: str = Field(..., description="'SUCCESS' or 'FAIL'")
    IP: str = Field(..., description="Client IP address")
    Endpoint: Optional[str] = "/api/auth/login"
    StatusCode: Optional[int] = 200
    Message: Optional[str] = None
    UserAgent: Optional[str] = None
