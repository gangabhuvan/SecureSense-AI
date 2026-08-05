"""
crud.py

Database operations for SecureSense AI.
"""

from typing import List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.models import Communication
from app.models.analysis_models import AnalysisResult


# ==========================================================
# Update
# ==========================================================

# ==========================================================
# Dashboard
# ==========================================================

def get_recent_uploads(
    db: Session,
    limit: int = 5,
) -> List[Communication]:
    """
    Get the most recent uploaded documents.
    """

    return (
        db.query(Communication)
        .order_by(
            Communication.uploaded_at.desc()
        )
        .limit(limit)
        .all()
    )


def get_document_type_counts(
    db: Session,
) -> dict[str, int]:
    """
    Get the number of documents for each detected
    document type.
    """

    results = (
        db.query(
            Communication.document_type,
            func.count(Communication.id),
        )
        .group_by(
            Communication.document_type
        )
        .all()
    )

    return {
        document_type if document_type else "Unknown": count
        for document_type, count in results
    }

def update_analysis(
    db: Session,
    communication: Communication,
    result: AnalysisResult,
    processing_time: float | None = None,
) -> Communication:
    """
    Update an existing Communication with OCR
    analysis results.
    """

    communication.risk_score = result.risk_score
    communication.risk_level = result.risk_level
    communication.confidence = result.confidence

    communication.document_type = result.document_type
    communication.document_confidence = result.document_confidence

    communication.summary = result.summary

    communication.entities = result.entities

    communication.findings = [
        finding.__dict__
        for finding in result.findings
    ]

    communication.processing_time = processing_time

    communication.status = "Completed"

    db.commit()
    db.refresh(communication)

    return communication


# ==========================================================
# Read
# ==========================================================

def get_communication_by_id(
    db: Session,
    communication_id: str,
) -> Optional[Communication]:
    """
    Get a Communication using its communication ID.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.communication_id == communication_id
        )
        .first()
    )


def get_upload_history(
    db: Session,
    risk_level: str | None = None,
    document_type: str | None = None,
    status: str | None = None,
    filename: str | None = None,
    skip: int = 0,
    limit: int = 100,
) -> List[Communication]:
    """
    Get upload history with optional filtering.
    """

    query = db.query(Communication)

    # ---------------------------------------------------------
    # Filters
    # ---------------------------------------------------------

    if risk_level:
        query = query.filter(
            Communication.risk_level == risk_level
        )

    if document_type:
        query = query.filter(
            Communication.document_type == document_type
        )

    if status:
        query = query.filter(
            Communication.status == status
        )

    if filename:
        query = query.filter(
            Communication.filename.ilike(f"%{filename}%")
        )

    # ---------------------------------------------------------
    # Sorting + Pagination
    # ---------------------------------------------------------

    return (
        query.order_by(
            Communication.uploaded_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


# ==========================================================
# Delete
# ==========================================================

def delete_communication(
    db: Session,
    communication_id: str,
) -> bool:
    """
    Delete a Communication.
    """

    communication = get_communication_by_id(
        db,
        communication_id
    )

    if communication is None:
        return False

    db.delete(communication)

    db.commit()

    return True


# ==========================================================
# Statistics
# ==========================================================

def get_total_communications(
    db: Session,
) -> int:
    """
    Total uploaded documents.
    """

    return db.query(
        Communication
    ).count()


def get_processed_documents_count(
    db: Session,
) -> int:
    """
    Number of successfully processed documents.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.status == "Completed"
        )
        .count()
    )


def get_failed_documents_count(
    db: Session,
) -> int:
    """
    Number of failed documents.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.status == "Failed"
        )
        .count()
    )


def get_high_risk_count(
    db: Session,
) -> int:
    """
    Number of High Risk documents.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.risk_level == "High"
        )
        .count()
    )


def get_medium_risk_count(
    db: Session,
) -> int:
    """
    Number of Medium Risk documents.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.risk_level == "Medium"
        )
        .count()
    )


def get_low_risk_count(
    db: Session,
) -> int:
    """
    Number of Low Risk documents.
    """

    return (
        db.query(Communication)
        .filter(
            Communication.risk_level == "Low"
        )
        .count()
    )