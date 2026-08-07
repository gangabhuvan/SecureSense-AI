"""
security.py

Password hashing utilities for SecureSense AI.
"""

from pwdlib import PasswordHash

# ==========================================================
# Password Hasher
# ==========================================================

password_hash = PasswordHash.recommended()


# ==========================================================
# Hash Password
# ==========================================================

def hash_password(password: str) -> str:
    """
    Hash a plain-text password.
    """
    return password_hash.hash(password)


# ==========================================================
# Verify Password
# ==========================================================

def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:
    """
    Verify a plain-text password against a stored hash.
    """
    return password_hash.verify(
        plain_password,
        hashed_password,
    )