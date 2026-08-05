"""
dashboard.py

Dashboard API endpoints for SecureSense AI.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
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
""",
)
def get_dashboard(
    db: Session = Depends(get_db),
):
    """
    Retrieve dashboard statistics.
    """

    return dashboard_service.get_dashboard_data(db)