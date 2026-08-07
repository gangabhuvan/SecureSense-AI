"""
visual.py

SecureSense AI Visual Phishing Intelligence API.

Pipeline:
    Website screenshot
        ↓
    Image validation
        ↓
    Reusable Visual Analysis Service
        ↓
    Frozen ConvNeXt-Tiny
        ↓
    Predicted-class Grad-CAM
        ↓
    Explainable Evidence Ledger (EEL)
        ↓
    Financial Communication Passport (FCP)
"""

from io import BytesIO
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
)
from app.core.auth import get_current_user
from app.database.models import User
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel

from app.fcp.generator import passport_generator
from app.fcp.models import FinancialCommunicationPassport

from app.services.visual_analysis_service import (
    visual_analysis_service,
)


# ============================================================
# Router
# ============================================================

router = APIRouter(
    prefix="/visual",
    tags=["Visual Phishing Intelligence"],
)


# ============================================================
# Configuration
# ============================================================

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB

ALLOWED_CONTENT_TYPES = {
    "image/png",
    "image/jpeg",
    "image/webp",
}


# ============================================================
# Response Schemas
# ============================================================

class VisualAttentionPointResponse(BaseModel):

    x: int
    y: int

    x_normalized: float
    y_normalized: float


class VisualExplanationResponse(BaseModel):

    method: str

    target_class: int
    target_label: str
    target_probability: float

    target_layer: str

    image_width: int
    image_height: int

    mean_attention: float
    max_attention: float
    high_attention_ratio: float

    max_attention_point: VisualAttentionPointResponse


class VisualAnalysisResponse(BaseModel):

    filename: str

    label: str
    class_id: int

    confidence: float
    confidence_percent: float

    phishing_probability: float
    phishing_probability_percent: float

    legitimate_probability: float
    legitimate_probability_percent: float

    risk_score: float

    decision_threshold: float

    image_width: int
    image_height: int

    explanation: VisualExplanationResponse

    model_info: Dict[str, Any]

    inference_time_ms: float

    # EEL audit identifiers
    evidence_id: str
    ledger_id: str

    # Financial Communication Passport
    passport: FinancialCommunicationPassport


# ============================================================
# Analyse Screenshot
# ============================================================

@router.post(
    "/analyse",
    response_model=VisualAnalysisResponse,
)
async def analyse_visual(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """
    Analyse a website screenshot using the reusable SecureSense
    visual intelligence pipeline.

    The pipeline performs:

    - Frozen ConvNeXt-Tiny inference
    - Predicted-class Grad-CAM
    - EEL evidence generation
    - Financial Communication Passport generation
    """

    image: Optional[Image.Image] = None

    try:

        # ----------------------------------------------------
        # 1. Validate content type
        # ----------------------------------------------------

        if (
            file.content_type
            not in ALLOWED_CONTENT_TYPES
        ):

            raise HTTPException(
                status_code=415,
                detail=(
                    "Unsupported image type. "
                    "Allowed types: PNG, JPEG and WEBP."
                ),
            )

        # ----------------------------------------------------
        # 2. Read uploaded image
        # ----------------------------------------------------

        contents = await file.read()

        if not contents:

            raise HTTPException(
                status_code=400,
                detail="Uploaded image is empty.",
            )

        if len(contents) > MAX_FILE_SIZE:

            raise HTTPException(
                status_code=413,
                detail=(
                    "Image exceeds maximum "
                    "allowed size of 10 MiB."
                ),
            )

        # ----------------------------------------------------
        # 3. Decode image
        # ----------------------------------------------------

        try:

            image = Image.open(
                BytesIO(contents)
            )

            image.load()

            image = image.convert(
                "RGB"
            )

        except (
            UnidentifiedImageError,
            OSError,
        ) as exc:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Uploaded file is not a "
                    "valid readable image."
                ),
            ) from exc

        # ----------------------------------------------------
        # 4. Validate dimensions
        # ----------------------------------------------------

        image_width, image_height = (
            image.size
        )

        if (
            image_width <= 0
            or image_height <= 0
        ):

            raise HTTPException(
                status_code=400,
                detail="Invalid image dimensions.",
            )

        filename = (
            file.filename
            or "uploaded_image"
        )

        # ----------------------------------------------------
        # 5. Reusable visual intelligence pipeline
        #
        # Performs:
        # - ConvNeXt inference
        # - predicted-class Grad-CAM
        # - consistency validation
        # - VisualEvidence creation
        # - EEL commit
        # ----------------------------------------------------

        visual_analysis = (
            visual_analysis_service.analyse(

                image,

                input_reference=filename,

                content_type=file.content_type,

                file_size_bytes=len(contents),
            )
        )

        result = visual_analysis[
            "prediction"
        ]

        visual_evidence = visual_analysis[
            "visual_explanation"
        ]

        evidence = visual_analysis[
            "evidence"
        ]

        ledger_entry = visual_analysis[
            "ledger_entry"
        ]

        # ----------------------------------------------------
        # 6. Generate standalone visual FCP
        #
        # /visual/analyse remains a standalone endpoint, so it
        # still produces its own visual Financial Communication
        # Passport.
        #
        # /upload/ will later use the same visual service while
        # composing communication-level multimodal evidence.
        # ----------------------------------------------------

        passport = (
            passport_generator.generate_from_eel(

                ledger_entry=ledger_entry,

                communication_id=(
                    evidence.evidence_id
                ),

                communication_type=(
                    "Website Screenshot"
                ),

                claimed_sender=(
                    "Unknown"
                ),
            )
        )

        # ----------------------------------------------------
        # 7. Build API response
        # ----------------------------------------------------

        return VisualAnalysisResponse(

            filename=filename,

            label=result[
                "label"
            ],

            class_id=result[
                "class_id"
            ],

            confidence=result[
                "confidence"
            ],

            confidence_percent=result[
                "confidence_percent"
            ],

            phishing_probability=result[
                "phishing_probability"
            ],

            phishing_probability_percent=result[
                "phishing_probability_percent"
            ],

            legitimate_probability=result[
                "legitimate_probability"
            ],

            legitimate_probability_percent=result[
                "legitimate_probability_percent"
            ],

            # Direct trained-model phishing probability × 100.
            risk_score=result[
                "risk_score"
            ],

            decision_threshold=result[
                "decision_threshold"
            ],

            image_width=visual_analysis[
                "image_width"
            ],

            image_height=visual_analysis[
                "image_height"
            ],

            explanation=(
                VisualExplanationResponse(

                    method=(
                        visual_evidence.method
                    ),

                    target_class=(
                        visual_evidence.target_class
                    ),

                    target_label=(
                        visual_evidence.target_label
                    ),

                    target_probability=(
                        visual_evidence.target_probability
                    ),

                    target_layer=(
                        visual_evidence.target_layer
                    ),

                    image_width=(
                        visual_evidence.image_width
                    ),

                    image_height=(
                        visual_evidence.image_height
                    ),

                    mean_attention=(
                        visual_evidence.mean_attention
                    ),

                    max_attention=(
                        visual_evidence.max_attention
                    ),

                    high_attention_ratio=(
                        visual_evidence.high_attention_ratio
                    ),

                    max_attention_point=(
                        VisualAttentionPointResponse(

                            x=(
                                visual_evidence
                                .max_attention_point
                                .x
                            ),

                            y=(
                                visual_evidence
                                .max_attention_point
                                .y
                            ),

                            x_normalized=(
                                visual_evidence
                                .max_attention_point
                                .x_normalized
                            ),

                            y_normalized=(
                                visual_evidence
                                .max_attention_point
                                .y_normalized
                            ),
                        )
                    ),
                )
            ),

            model_info=result[
                "model_info"
            ],

            inference_time_ms=result[
                "inference_time_ms"
            ],

            evidence_id=(
                evidence.evidence_id
            ),

            ledger_id=(
                ledger_entry.ledger_id
            ),

            passport=passport,
        )

    except HTTPException:

        raise

    except (
        ValueError,
        FileNotFoundError,
        TypeError,
    ) as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Visual analysis failed: "
                f"{str(exc)}"
            ),
        ) from exc

    finally:

        if image is not None:
            image.close()

        await file.close()