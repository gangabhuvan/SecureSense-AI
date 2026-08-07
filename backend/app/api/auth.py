"""
auth.py

Authentication API for SecureSense AI.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import (
    create_access_token,
    get_current_user,
)
from app.database.database import get_db
from app.database.models import User
from app.schemas.auth import (
    Token,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services.auth_service import auth_service

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# ==========================================================
# Register
# ==========================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register(
    request: UserRegister,
    db: Session = Depends(get_db),
):
    """
    Create a new SecureSense AI user account.
    """

    # Username already exists
    if auth_service.get_user(db, request.username):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )

    # Email already exists
    if auth_service.get_user_by_email(db, request.email):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered.",
        )

    user = auth_service.create_user(
        db=db,
        username=request.username,
        email=request.email,
        password=request.password,
    )

    return user


# ==========================================================
# Login
# ==========================================================

@router.post(
    "/login",
    response_model=Token,
    summary="Authenticate user",
)
def login(
    request: UserLogin,
    db: Session = Depends(get_db),
):
    """
    Authenticate a user and return a JWT access token.
    """

    user = auth_service.authenticate(
        db=db,
        username=request.username,
        password=request.password,
    )

    if user is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    access_token = create_access_token(
        {
            "sub": user.username
        }
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
    )


# ==========================================================
# Current User
# ==========================================================

@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user",
)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Return the currently authenticated user.
    """

    return current_user