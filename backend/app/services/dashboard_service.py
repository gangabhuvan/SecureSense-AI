"""
dashboard_service.py

Business logic for the Dashboard API.
"""

from sqlalchemy.orm import Session

from app import crud
from app.schemas.dashboard_schema import (
    DashboardResponse,
    Overview,
    RecentUpload,
    RiskDistribution,
)


class DashboardService:
    """
    Service for building dashboard statistics.
    """

    def get_dashboard_data(
        self,
        db: Session,
    ) -> DashboardResponse:

        # ---------------------------------------------------------
        # Overview
        # ---------------------------------------------------------

        overview = Overview(
            total_documents=crud.get_total_communications(db),
            processed_documents=crud.get_processed_documents_count(db),
            failed_documents=crud.get_failed_documents_count(db),
        )

        # ---------------------------------------------------------
        # Risk Distribution
        # ---------------------------------------------------------

        risk_distribution = RiskDistribution(
            high=crud.get_high_risk_count(db),
            medium=crud.get_medium_risk_count(db),
            low=crud.get_low_risk_count(db),
        )

        # ---------------------------------------------------------
        # Document Types
        # ---------------------------------------------------------

        document_types = crud.get_document_type_counts(db)

        # ---------------------------------------------------------
        # Recent Uploads
        # ---------------------------------------------------------

        recent_uploads = [
            RecentUpload(
                communication_id=item.communication_id,
                filename=item.filename,
                file_type=item.file_type,
                risk_level=item.risk_level,
                status=item.status,
                uploaded_at=item.uploaded_at,
            )
            for item in crud.get_recent_uploads(db)
        ]

        # ---------------------------------------------------------
        # Response
        # ---------------------------------------------------------

        return DashboardResponse(
            overview=overview,
            risk_distribution=risk_distribution,
            document_types=document_types,
            recent_uploads=recent_uploads,
        )


dashboard_service = DashboardService()