from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Communication
from app.schemas.ocr_schema import OCRResponse
from app.services.ocr_service import ocr_service

router = APIRouter(
    prefix="/ocr",
    tags=["OCR"]
)


@router.post("/{communication_id}", response_model=OCRResponse)
def perform_ocr(
    communication_id: str,
    db: Session = Depends(get_db)
):

    communication = (
        db.query(Communication)
        .filter(
            Communication.communication_id == communication_id
        )
        .first()
    )

    if communication is None:
        raise HTTPException(
            status_code=404,
            detail="Communication not found."
        )

    try:

        extracted_text = ocr_service.extract_text(
            communication.filepath
        )

        communication.extracted_text = extracted_text
        communication.ocr_status = "Completed"

        db.commit()
        db.refresh(communication)

        return OCRResponse(
            communication_id=communication.communication_id,
            filename=communication.filename,
            ocr_status=communication.ocr_status,
            extracted_text=communication.extracted_text,
            text_length=len(communication.extracted_text)
        )

    except Exception as e:

        communication.ocr_status = "Failed"
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )