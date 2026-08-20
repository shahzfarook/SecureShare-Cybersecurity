"""
User Storage & Repository Module
Author: Anuraj
Provides thread-safe in-memory/sqlite user persistence with seeded default accounts.
"""

from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional
import uuid

try:
    from .models import UserRole
    from .security import hash_password
except (ImportError, ValueError):
    from models import UserRole
    from security import hash_password


class UserRecord:
    """Internal user representation with hashed credentials."""

    def __init__(
        self,
        id: str,
        username: str,
        email: str,
        hashed_password: str,
        role: UserRole = UserRole.USER,
        name: Optional[str] = None,
        is_active: bool = True,
        created_at: Optional[datetime] = None,
    ):
        self.id = id
        self.username = username.lower().strip()
        self.email = email.lower().strip()
        self.hashed_password = hashed_password
        self.role = role if isinstance(role, UserRole) else UserRole(str(role).lower())
        self.name = name or username
        self.is_active = is_active
        self.created_at = created_at or datetime.now(timezone.utc)

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "name": self.name,
            "role": self.role.value if isinstance(self.role, UserRole) else str(self.role),
            "is_active": self.is_active,
            "created_at": self.created_at,
        }


class UserRepository:
    """Thread-safe storage repository for users."""

    def __init__(self):
        self._lock = threading.RLock()
        self._users_by_id: Dict[str, UserRecord] = {}
        self._users_by_email: Dict[str, str] = {}  # email -> id
        self._users_by_username: Dict[str, str] = {}  # username -> id
        self._seed_default_users()

    def _seed_default_users(self):
        """Seed default admin and standard user accounts for testing & development."""
        # 1. Admin Account
        admin_email = "admin@secureshare.local"
        if admin_email not in self._users_by_email:
            admin_user = UserRecord(
                id=str(uuid.uuid4()),
                username="admin",
                email=admin_email,
                name="Security Administrator",
                hashed_password=hash_password("Admin@123456"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            self._insert(admin_user)

        # 2. Standard User Account
        user_email = "user@secureshare.local"
        if user_email not in self._users_by_email:
            standard_user = UserRecord(
                id=str(uuid.uuid4()),
                username="user",
                email=user_email,
                name="Standard User",
                hashed_password=hash_password("User@123456"),
                role=UserRole.USER,
                is_active=True,
            )
            self._insert(standard_user)

    def _insert(self, user: UserRecord):
        self._users_by_id[user.id] = user
        self._users_by_email[user.email.lower()] = user.id
        self._users_by_username[user.username.lower()] = user.id

    def create_user(
        self,
        email: str,
        password: str,
        username: Optional[str] = None,
        name: Optional[str] = None,
        role: UserRole = UserRole.USER,
    ) -> UserRecord:
        """Create and store a new user with hashed password."""
        email_clean = email.strip().lower()
        if not username or not username.strip():
            username_clean = email_clean.split("@")[0]
        else:
            username_clean = username.strip().lower()

        with self._lock:
            if email_clean in self._users_by_email:
                raise ValueError(f"User with email '{email_clean}' already exists.")
            if username_clean in self._users_by_username:
                raise ValueError(f"Username '{username_clean}' is already taken.")

            user = UserRecord(
                id=str(uuid.uuid4()),
                username=username_clean,
                email=email_clean,
                name=name or username_clean,
                hashed_password=hash_password(password),
                role=role if isinstance(role, UserRole) else UserRole(role),
                is_active=True,
            )
            self._insert(user)
            return user

    def get_by_id(self, user_id: str) -> Optional[UserRecord]:
        with self._lock:
            return self._users_by_id.get(user_id)

    def get_by_email(self, email: str) -> Optional[UserRecord]:
        with self._lock:
            user_id = self._users_by_email.get(email.strip().lower())
            return self._users_by_id.get(user_id) if user_id else None

    def get_by_username(self, username: str) -> Optional[UserRecord]:
        with self._lock:
            user_id = self._users_by_username.get(username.strip().lower())
            return self._users_by_id.get(user_id) if user_id else None

    def get_by_identifier(self, identifier: str) -> Optional[UserRecord]:
        """Find user by email or username."""
        clean_id = identifier.strip().lower()
        user = self.get_by_email(clean_id)
        if not user:
            user = self.get_by_username(clean_id)
        return user

    def list_all(self) -> List[UserRecord]:
        with self._lock:
            return list(self._users_by_id.values())

    def update_role(self, user_id: str, new_role: UserRole) -> Optional[UserRecord]:
        with self._lock:
            user = self._users_by_id.get(user_id)
            if user:
                user.role = new_role if isinstance(new_role, UserRole) else UserRole(new_role)
            return user

    def clear(self):
        """Reset repository for unit tests."""
        with self._lock:
            self._users_by_id.clear()
            self._users_by_email.clear()
            self._users_by_username.clear()
            self._seed_default_users()


# Global Singleton Repository Instance
user_repository = UserRepository()
