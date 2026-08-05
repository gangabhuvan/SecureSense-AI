"""
reports.py

SecureSense AI downloadable security report API.

Reports are generated exclusively from persisted investigation
state and auditable evidence.

No AI inference or analysis pipeline is rerun when a report is
downloaded.
"""

from __future__ import annotations

from io import BytesIO

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import (
    Communication,
    EELEntry,
    STGObservation,
)
from app.services.report_service import (
    report_service,
)


# ============================================================
# Router
# ============================================================

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


# ============================================================
# Download Security Investigation Report
# ============================================================

@router.get(
    "/{communication_id}/pdf",
    summary="Download security investigation report",
    description="""
Generate a SecureSense AI Security Investigation Report from
persisted investigation data.

The report includes available:

- final communication-level security assessment
- Financial Communication Passport
- sender authenticity verification
- multimodal intelligence
- Securities Trust Graph context
- Explainable Evidence Ledger provenance
- final security recommendation

Report generation is read-only and does not rerun AI models.
""",
    response_class=StreamingResponse,
)
def download_security_report(
    communication_id: str,
    db: Session = Depends(get_db),
):
    """
    Generate a PDF report for one persisted communication.
    """

    # ========================================================
    # 1. Load Communication
    # ========================================================

    communication = (
        db.query(Communication)
        .filter(
            Communication.communication_id
            == communication_id
        )
        .first()
    )

    if communication is None:
        raise HTTPException(
            status_code=404,
            detail="Communication not found",
        )

    # ========================================================
    # 2. Require Completed Investigation
    # ========================================================

    status = str(
        communication.status or ""
    ).strip().lower()

    if status != "completed":
        raise HTTPException(
            status_code=409,
            detail=(
                "Security report is available only for "
                "completed investigations."
            ),
        )

    # ========================================================
    # 3. Load Persisted EEL Records
    # ========================================================

    eel_entries = (
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

    # ========================================================
    # 4. Load Persisted STG Observations
    # ========================================================

    stg_observations = (
        db.query(STGObservation)
        .filter(
            STGObservation.communication_id
            == communication_id
        )
        .order_by(
            STGObservation.observed_at.asc()
        )
        .all()
    )

    # ========================================================
    # 5. Generate Report From Persisted State
    # ========================================================

    try:
        pdf_bytes = report_service.generate(
            communication=communication,
            eel_entries=eel_entries,
            stg_observations=stg_observations,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to generate security "
                f"report: {exc}"
            ),
        ) from exc

    if not pdf_bytes:
        raise HTTPException(
            status_code=500,
            detail="Generated report is empty.",
        )

    # ========================================================
    # 6. Safe Download Filename
    # ========================================================

    safe_id = "".join(
        character
        if (
            character.isalnum()
            or character in {"-", "_"}
        )
        else "_"
        for character in communication_id
    )

    filename = (
        f"SecureSense_AI_Security_Report_"
        f"{safe_id}.pdf"
    )

    # ========================================================
    # 7. Stream PDF
    # ========================================================

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": (
                "private, no-store, max-age=0"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )