"""
auth.py

Pydantic schemas for SecureSense AI authentication.
"""

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
)


# ==========================================================
# Registration Request
# ==========================================================

class UserRegister(BaseModel):
    """
    User registration request.
    """

    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        description="Unique username",
        examples=["Bhuvan"],
    )

    email: EmailStr = Field(
        ...,
        description="User email address",
        examples=["gangapatri32@gmail.com"],
    )

    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password",
        examples=["SecureSense@123"],
    )


# ==========================================================
# Login Request
# ==========================================================

class UserLogin(BaseModel):
    """
    User login request.
    """

    username: str = Field(
        ...,
        description="Registered username",
        examples=["Bhuvan"],
    )

    password: str = Field(
        ...,
        description="Account password",
        examples=["SecureSense@123"],
    )


# ==========================================================
# JWT Response
# ==========================================================

class Token(BaseModel):
    """
    JWT authentication response.
    """

    access_token: str
    token_type: str = "bearer"


# ==========================================================
# JWT Payload
# ==========================================================

class TokenData(BaseModel):
    """
    JWT payload.
    """

    username: str | None = None


# ==========================================================
# Public User Response
# ==========================================================

class UserResponse(BaseModel):
    """
    Public user information.
    """

    id: int
    username: str
    email: EmailStr
    is_active: bool

    model_config = ConfigDict(
        from_attributes=True
    )