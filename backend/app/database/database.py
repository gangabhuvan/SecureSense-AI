"""
database.py

Database configuration for SecureSense AI.

Provides:
- SQLAlchemy Engine
- SessionLocal
- Base
- Database dependency for FastAPI
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

# ==========================================================
# Database Configuration
# ==========================================================

DATABASE_URL = "sqlite:///./securesense.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# ==========================================================
# Dependency
# ==========================================================

def get_db():
    """
    FastAPI database dependency.

    Usage:
        db: Session = Depends(get_db)
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ==========================================================
# Database Initialization
# ==========================================================

def init_db():
    """
    Create all database tables.
    """

    Base.metadata.create_all(bind=engine)