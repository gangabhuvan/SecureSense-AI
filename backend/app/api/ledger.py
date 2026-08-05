"""
ledger.py

Durable Explainable Evidence Ledger API.

Provides read-only access to evidence persisted in the
eel_entries database table.

The database is the authoritative source for historical EEL
retrieval. The in-memory evidence ledger is intentionally not
used by these endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)

from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import EELEntry


router = APIRouter(
    prefix="/ledger",
    tags=["Explainable Evidence Ledger"],
)


# ==========================================================
# Helpers
# ==========================================================

def _serialize_entry(
    entry: EELEntry,
) -> dict[str, Any]:
    """
    Convert one persisted EEL ORM row into an API-safe
    dictionary.
    """

    return {
        "ledger_id": entry.ledger_id,
        "evidence_id": entry.evidence_id,
        "communication_id": entry.communication_id,
        "module": entry.module,
        "evidence_type": entry.evidence_type,
        "prediction": entry.prediction,
        "confidence": entry.confidence,
        "risk_score": entry.risk_score,
        "recorded_at": entry.recorded_at,
        "evidence": entry.evidence,
    }


# ==========================================================
# Ledger History
# ==========================================================

@router.get(
    "",
    summary="Get Explainable Evidence Ledger history",
)
def get_ledger_history(
    communication_id: str | None = Query(
        default=None
    ),
    module: str | None = Query(
        default=None
    ),
    prediction: str | None = Query(
        default=None
    ),
    skip: int = Query(
        default=0,
        ge=0,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    db: Session = Depends(get_db),
):
    """
    Return persisted EEL entries.

    Optional filters:
    - communication_id
    - module
    - prediction
    """

    query = db.query(
        EELEntry
    )

    if communication_id:

        query = query.filter(
            EELEntry.communication_id
            == communication_id
        )

    if module:

        query = query.filter(
            EELEntry.module == module
        )

    if prediction:

        query = query.filter(
            EELEntry.prediction == prediction
        )

    total = query.count()

    entries = (
        query
        .order_by(
            EELEntry.recorded_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "entries": [
            _serialize_entry(entry)
            for entry in entries
        ],
    }


# ==========================================================
# Evidence for Communication
# ==========================================================

@router.get(
    "/communication/{communication_id}",
    summary="Get evidence for a communication",
)
def get_communication_evidence(
    communication_id: str,
    db: Session = Depends(get_db),
):
    """
    Return every durable EEL entry associated with one
    communication.
    """

    entries = (
        db.query(EELEntry)
        .filter(
            EELEntry.communication_id
            == communication_id
        )
        .order_by(
            EELEntry.recorded_at.asc()
        )
        .all()
    )

    return {
        "communication_id": communication_id,
        "count": len(entries),
        "entries": [
            _serialize_entry(entry)
            for entry in entries
        ],
    }


# ==========================================================
# Individual Ledger Entry
# ==========================================================

@router.get(
    "/{ledger_id}",
    summary="Get a complete ledger entry",
)
def get_ledger_entry(
    ledger_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve one complete persisted EEL entry including its
    explainability evidence.
    """

    entry = (
        db.query(EELEntry)
        .filter(
            EELEntry.ledger_id == ledger_id
        )
        .first()
    )

    if entry is None:

        raise HTTPException(
            status_code=404,
            detail="Ledger entry not found",
        )

    return _serialize_entry(
        entry
    )