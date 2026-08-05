"""
analysis.py

Unified SecureSense AI analysis endpoint.

Users may provide either:
- An uploaded document/image
- Pasted communication text

The extracted/received text is passed through the complete
SecureSense analysis pipeline, including DistilBERT NLP,
rule-based detection, entity extraction, context detection,
hybrid risk scoring, and Financial Communication Passport.
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import AnalysisResponse
from app.services.analysis_service import analysis_service
from app.services.ocr_service import ocr_service


router = APIRouter(
    prefix="/analysis",
    tags=["Analysis"],
)


# ==========================================================
# Configuration
# ==========================================================

UPLOAD_DIR = Path("uploads")

UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


ALLOWED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".tif",
    ".tiff",
}


MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

MAX_TEXT_LENGTH = 100_000


# ==========================================================
# Helpers
# ==========================================================

def _validate_text(text: str) -> str:
    """
    Validate and normalize directly supplied text.
    """

    text = text.strip()

    if not text:
        raise HTTPException(
            status_code=400,
            detail="Text input is empty.",
        )

    if len(text) > MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Text exceeds the maximum allowed length "
                f"of {MAX_TEXT_LENGTH:,} characters."
            ),
        )

    return text


def _extract_txt(content: bytes) -> str:
    """
    Decode a plain-text upload safely.
    """

    try:
        return content.decode("utf-8")

    except UnicodeDecodeError:

        try:
            return content.decode("utf-8-sig")

        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unable to decode the uploaded text file "
                    "as UTF-8."
                ),
            ) from exc


# ==========================================================
# Unified Analysis Endpoint
# ==========================================================

@router.post(
    "/analyse",
    response_model=AnalysisResponse,
)
async def analyse(
    file: Optional[UploadFile] = File(
        default=None,
        description="Upload a supported document or image.",
    ),
    text: Optional[str] = Form(
        default=None,
        description="Paste email, SMS, message, or other text.",
    ),
    db: Session = Depends(get_db),
):
    """
    Run the complete SecureSense analysis pipeline.

    Exactly one input must be supplied:

    1. file
       OR
    2. text
    """

    # ------------------------------------------------------
    # Validate input mode
    # ------------------------------------------------------

    has_file = (
        file is not None
        and bool(file.filename)
    )

    has_text = (
        text is not None
        and bool(text.strip())
    )

    if not has_file and not has_text:
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide either an uploaded file "
                "or pasted text."
            ),
        )

    if has_file and has_text:
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide only one input at a time: "
                "either a file or pasted text."
            ),
        )

    start_time = time.perf_counter()

    save_path: Optional[Path] = None

    source_filename = "pasted_text"
    source_extension = ".txt"

    try:

        # ==================================================
        # MODE 1 — Pasted Text
        # ==================================================

        if has_text:

            extracted_text = _validate_text(
                text
            )

        # ==================================================
        # MODE 2 — Uploaded File
        # ==================================================

        else:

            assert file is not None
            assert file.filename is not None

            original_filename = Path(
                file.filename
            ).name

            extension = Path(
                original_filename
            ).suffix.lower()

            if extension not in ALLOWED_EXTENSIONS:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Unsupported file format. "
                        f"Supported formats: "
                        f"{', '.join(sorted(ALLOWED_EXTENSIONS))}"
                    ),
                )

            content = await file.read()

            if not content:
                raise HTTPException(
                    status_code=400,
                    detail="Uploaded file is empty.",
                )

            if len(content) > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="File exceeds the 10 MB limit.",
                )

            source_filename = original_filename
            source_extension = extension

            # ----------------------------------------------
            # Plain text requires no OCR
            # ----------------------------------------------

            if extension == ".txt":

                extracted_text = _extract_txt(
                    content
                )

                extracted_text = _validate_text(
                    extracted_text
                )

            # ----------------------------------------------
            # PDF / image extraction
            # ----------------------------------------------

            else:

                unique_filename = (
                    f"{uuid.uuid4().hex}{extension}"
                )

                save_path = (
                    UPLOAD_DIR
                    / unique_filename
                )

                save_path.write_bytes(
                    content
                )

                extracted_text = (
                    ocr_service.extract_text(
                        str(save_path)
                    )
                )

                if (
                    not extracted_text
                    or not extracted_text.strip()
                ):
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            "No readable text could be "
                            "extracted from the uploaded file."
                        ),
                    )

                extracted_text = (
                    extracted_text.strip()
                )

        # ==================================================
        # Complete SecureSense Analysis
        # ==================================================

        result = analysis_service.analyse(
            extracted_text
        )

        processing_time = (
            time.perf_counter()
            - start_time
        )

        # ==================================================
        # Optional persistence
        # ==================================================
        #
        # Keep disabled until the database model is updated
        # for the unified NLP/hybrid response.
        #
        # create_analysis(
        #     db=db,
        #     filename=source_filename,
        #     file_type=source_extension.lstrip("."),
        #     ocr_text=extracted_text,
        #     result=result,
        #     processing_time=processing_time,
        # )

        # ==================================================
        # API Response
        # ==================================================

        return AnalysisResponse(
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            confidence=result.confidence,
            summary=result.summary,

            document_type=result.document_type,
            document_confidence=result.document_confidence,

            findings=result.findings,
            entities=result.entities,

            nlp=result.nlp,

            passport=result.passport,
        )

    # ======================================================
    # Preserve intentional HTTP errors
    # ======================================================

    except HTTPException:
        raise

    # ======================================================
    # Unexpected errors
    # ======================================================

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Analysis failed: {str(exc)}"
            ),
        ) from exc

    # ======================================================
    # Cleanup temporary upload
    # ======================================================

    finally:

        if (
            save_path is not None
            and save_path.exists()
        ):

            try:
                os.remove(
                    save_path
                )

            except OSError:
                pass