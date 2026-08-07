"""
auth_service.py

Authentication service for SecureSense AI.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.security import (
    hash_password,
    verify_password,
)
from app.database.models import User


class AuthService:
    """
    Authentication service.
    """

    # ==========================================================
    # Get User by Username
    # ==========================================================

    def get_user(
        self,
        db: Session,
        username: str,
    ) -> User | None:

        return (
            db.query(User)
            .filter(User.username == username)
            .first()
        )

    # ==========================================================
    # Get User by Email
    # ==========================================================

    def get_user_by_email(
        self,
        db: Session,
        email: str,
    ) -> User | None:

        return (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

    # ==========================================================
    # Create User
    # ==========================================================

    def create_user(
        self,
        db: Session,
        username: str,
        email: str,
        password: str,
    ) -> User:

        user = User(
            username=username.strip(),
            email=email.strip().lower(),
            hashed_password=hash_password(password),
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    # ==========================================================
    # Authenticate User
    # ==========================================================

    def authenticate(
        self,
        db: Session,
        username: str,
        password: str,
    ) -> User | None:

        user = self.get_user(
            db,
            username.strip(),
        )

        if user is None:
            return None

        if not user.is_active:
            return None

        if not verify_password(
            password,
            user.hashed_password,
        ):
            return None

        user.last_login = datetime.now(timezone.utc)

        db.commit()

        return user


auth_service = AuthService()