"""
dashboard.py

Dashboard API endpoints for SecureSense AI.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.database.database import get_db
from app.database.models import User
from app.schemas.dashboard_schema import DashboardResponse
from app.services.dashboard_service import dashboard_service

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get(
    "/",
    response_model=DashboardResponse,
    summary="Get dashboard statistics",
    description="""
Returns a dashboard summary including:

- Overall document statistics
- Risk level distribution
- Document type distribution
- Recent uploaded documents

Authentication required.
""",
)
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve dashboard statistics for the authenticated user.
    """

    return dashboard_service.get_dashboard_data(db)