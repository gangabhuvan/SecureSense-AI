"""
history.py

API endpoints for viewing and managing analysis history.
"""

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.crud import (
    delete_analysis,
    get_all_analyses,
    get_analysis,
)
from app.database import get_db
from app.schemas import (
    CommunicationDetailResponse,
    CommunicationResponse,
    MessageResponse,
)

router = APIRouter(
    prefix="/history",
    tags=["History"]
)


# ==========================================================
# Get Analysis History
# ==========================================================

@router.get(
    "/",
    response_model=list[CommunicationResponse],
)
def get_history(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """
    Return analysis history ordered by newest first.
    """

    return get_all_analyses(
        db=db,
        skip=skip,
        limit=limit,
    )


# ==========================================================
# Get Single Analysis
# ==========================================================

@router.get(
    "/{analysis_id}",
    response_model=CommunicationDetailResponse,
)
def get_analysis_by_id(
    analysis_id: int,
    db: Session = Depends(get_db),
):
    """
    Return one analysis by ID.
    """

    analysis = get_analysis(
        db=db,
        analysis_id=analysis_id,
    )

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    return analysis


# ==========================================================
# Delete Analysis
# ==========================================================

@router.delete(
    "/{analysis_id}",
    response_model=MessageResponse,
)
def delete_analysis_by_id(
    analysis_id: int,
    db: Session = Depends(get_db),
):
    """
    Delete an analysis.
    """

    deleted = delete_analysis(
        db=db,
        analysis_id=analysis_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    return MessageResponse(
        message="Analysis deleted successfully."
    )