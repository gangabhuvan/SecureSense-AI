"""
auth.py

JWT authentication utilities for SecureSense AI.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE,
    REFRESH_TOKEN_EXPIRE,
)
from app.database.database import get_db
from app.database.models import User


# ==========================================================
# OAuth2
# ==========================================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/auth/login"
)


# ==========================================================
# Create Access Token
# ==========================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Generate a signed JWT access token.

    Access tokens are short-lived and are used to
    authenticate normal API requests.
    """

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta or ACCESS_TOKEN_EXPIRE
    )

    to_encode.update(
        {
            "exp": expire,
            "type": "access",
        }
    )

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return encoded_jwt


# ==========================================================
# Create Refresh Token
# ==========================================================

def create_refresh_token(
    data: dict,
) -> str:
    """
    Generate a signed JWT refresh token.

    Refresh tokens have a longer lifetime and are used
    only to obtain new access tokens.
    """

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + REFRESH_TOKEN_EXPIRE

    to_encode.update(
        {
            "exp": expire,
            "type": "refresh",
        }
    )

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return encoded_jwt


# ==========================================================
# Decode Access Token
# ==========================================================

def decode_access_token(
    token: str,
) -> dict:
    """
    Decode and validate a JWT access token.
    """

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        # Prevent refresh tokens from being used
        # as normal access tokens.
        if payload.get("type") != "access":

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid access token.",
                headers={
                    "WWW-Authenticate": "Bearer"
                },
            )

        return payload

    except HTTPException:
        raise

    except JWTError:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )


# ==========================================================
# Decode Refresh Token
# ==========================================================

def decode_refresh_token(
    token: str,
) -> dict:
    """
    Decode and validate a JWT refresh token.
    """

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        # Prevent access tokens from being used
        # as refresh tokens.
        if payload.get("type") != "refresh":

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token.",
            )

        return payload

    except HTTPException:
        raise

    except JWTError:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )


# ==========================================================
# Current User Dependency
# ==========================================================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Return the currently authenticated user.
    """

    payload = decode_access_token(token)

    username = payload.get("sub")

    if username is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is invalid.",
        )

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )

    return user