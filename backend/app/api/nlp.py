"""
nlp.py

SecureSense AI NLP Security Analysis API.

Pipeline:
    Email / text
        ↓
    Frozen DistilBERT
        ↓
    Legitimate / Spam / Phishing
        ↓
    Integrated Gradients
        ↓
    Explainable Evidence Ledger (EEL)
        ↓
    Financial Communication Passport (FCP)
"""

from __future__ import annotations

import logging
from typing import Dict, List

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from app.core.auth import get_current_user
from app.database.models import User
from pydantic import BaseModel, Field

from app.ai.nlp.predictor import predict_email

from app.services.nlp_explainability_service import (
    nlp_explainability_service,
)

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
    NLPExplanationEvidence,
    TokenEvidence,
)

from app.eel.ledger import (
    evidence_ledger,
)

from app.fcp.generator import (
    passport_generator,
)

from app.fcp.models import (
    FinancialCommunicationPassport,
)


logger = logging.getLogger(__name__)


# ==========================================================
# Router
# ==========================================================

router = APIRouter(
    prefix="/nlp",
    tags=["NLP Security Analysis"],
)


# ==========================================================
# Request Schema
# ==========================================================

class NLPAnalysisRequest(BaseModel):
    """
    Request payload for NLP classification.
    """

    text: str = Field(
        ...,
        min_length=1,
        description="Email or extracted text to analyse.",
    )


# ==========================================================
# Explainability Schemas
# ==========================================================

class NLPTokenEvidenceResponse(BaseModel):

    token: str

    token_index: int

    attribution: float

    strength: float

    normalized_strength: float

    direction: str


class NLPExplanationResponse(BaseModel):

    method: str

    predicted_class: int

    predicted_label: str

    target_class: int

    target_label: str

    target_probability: float

    steps: int

    token_count: int

    top_tokens: List[
        NLPTokenEvidenceResponse
    ]


# ==========================================================
# Response Schema
# ==========================================================

class NLPAnalysisResponse(BaseModel):

    label: str

    class_id: int

    confidence: float

    confidence_percent: float

    probabilities: Dict[
        str,
        float,
    ]

    inference_time_ms: float

    explanation: (
        NLPExplanationResponse
    )

    evidence_id: str

    ledger_id: str

    passport: (
        FinancialCommunicationPassport
    )


# ==========================================================
# Health Endpoint
# ==========================================================

@router.get(
    "/health",
    summary="Check NLP service health",
)
def nlp_health():
    """
    Lightweight NLP health endpoint.

    This does not force model loading.
    """

    return {
        "status": "ok",
        "service": (
            "distilbert_nlp_classifier"
        ),
    }


# ==========================================================
# Risk Mapping
# ==========================================================

def _calculate_risk_score(
    label: str,
    probabilities: Dict[str, float],
) -> float:
    """
    Convert the three-class DistilBERT output into the
    SecureSense 0-100 risk scale.

    The model currently returns class probabilities as
    percentages.

    Risk semantics:
        Legitimate -> low threat probability
        Spam       -> suspicious but lower severity
        Phishing   -> direct phishing risk

    Phishing probability receives full weight.
    Spam probability receives partial weight.
    """

    phishing_probability = float(
        probabilities.get(
            "Phishing",
            0.0,
        )
    )

    spam_probability = float(
        probabilities.get(
            "Spam",
            0.0,
        )
    )

    risk_score = (
        phishing_probability
        + (0.50 * spam_probability)
    )

    return round(
        max(
            0.0,
            min(
                100.0,
                risk_score,
            ),
        ),
        4,
    )


# ==========================================================
# Classification Endpoint
# ==========================================================

@router.post(
    "/predict",
    response_model=NLPAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary=(
        "Analyse text using DistilBERT, "
        "Integrated Gradients, EEL and FCP"
    ),
)
def predict_text(
    request: NLPAnalysisRequest,
    current_user: User = Depends(get_current_user),
    
) -> NLPAnalysisResponse:
    """
    Analyse supplied text using the complete SecureSense
    NLP trust-intelligence pipeline.

    Produces:

        1. DistilBERT classification
        2. Integrated Gradients explanation
        3. EEL evidence record
        4. Financial Communication Passport
    """

    try:

        # ----------------------------------------------------
        # 1. Frozen DistilBERT prediction
        # ----------------------------------------------------

        result = predict_email(
            request.text
        )

        # ----------------------------------------------------
        # 2. Integrated Gradients
        #
        # Explain the class actually predicted by the same
        # frozen DistilBERT model.
        # ----------------------------------------------------

        explanation = (
            nlp_explainability_service.explain(
                request.text,
                target_class=(
                    result["class_id"]
                ),
                top_k=10,
            )
        )

        # ----------------------------------------------------
        # 3. Prediction consistency validation
        #
        # Prediction and explanation must refer to the exact
        # same model decision.
        # ----------------------------------------------------

        if (
            explanation[
                "predicted_class"
            ]
            != result["class_id"]
        ):

            raise RuntimeError(
                "NLP prediction/explanation "
                "class mismatch."
            )

        if (
            explanation[
                "predicted_label"
            ]
            != result["label"]
        ):

            raise RuntimeError(
                "NLP prediction/explanation "
                "label mismatch."
            )

        # ----------------------------------------------------
        # 4. Risk score
        # ----------------------------------------------------

        risk_score = (
            _calculate_risk_score(
                result["label"],
                result["probabilities"],
            )
        )

        # ----------------------------------------------------
        # 5. Convert token attribution into EEL models
        # ----------------------------------------------------

        token_evidence = [

            TokenEvidence(

                token=item["token"],

                token_index=(
                    item["token_index"]
                ),

                attribution=(
                    item["attribution"]
                ),

                strength=(
                    item["strength"]
                ),

                normalized_strength=(
                    item[
                        "normalized_strength"
                    ]
                ),

                direction=(
                    item["direction"]
                ),
            )

            for item
            in explanation["top_tokens"]
        ]

        nlp_evidence = (
            NLPExplanationEvidence(

                method=(
                    explanation["method"]
                ),

                target_class=(
                    explanation[
                        "target_class"
                    ]
                ),

                target_label=(
                    explanation[
                        "target_label"
                    ]
                ),

                target_probability=(
                    explanation[
                        "target_probability"
                    ]
                ),

                steps=(
                    explanation["steps"]
                ),

                token_count=(
                    explanation[
                        "token_count"
                    ]
                ),

                top_tokens=(
                    token_evidence
                ),
            )
        )

        # ----------------------------------------------------
        # 6. Create EEL evidence record
        # ----------------------------------------------------

        evidence_record = (
            EvidenceRecord(

                module=(
                    "NLP Security Analysis"
                ),

                evidence_type=(
                    "nlp_integrated_gradients"
                ),

                prediction=(
                    result["label"]
                ),

                class_id=(
                    result["class_id"]
                ),

                confidence=(
                    result["confidence"]
                ),

                risk_score=(
                    risk_score
                ),

                nlp_explanation=(
                    nlp_evidence
                ),

                model_info=(
                    EvidenceModelInfo(

                        module=(
                            "NLP Security Analysis"
                        ),

                        model_type=(
                            "DistilBERT"
                        ),

                        model_file=(
                            "model.safetensors"
                        ),

                        input_size=(
                            "256 tokens"
                        ),
                    )
                ),

                supporting_data={

                    "probabilities":
                        result[
                            "probabilities"
                        ],

                    "inference_time_ms":
                        result[
                            "inference_time_ms"
                        ],

                    "explanation_method":
                        explanation[
                            "method"
                        ],

                    "attribution_steps":
                        explanation[
                            "steps"
                        ],

                    "token_count":
                        explanation[
                            "token_count"
                        ],
                },
            )
        )

        # ----------------------------------------------------
        # 7. Commit to Explainable Evidence Ledger
        # ----------------------------------------------------

        ledger_entry = (
            evidence_ledger.record(
                evidence_record
            )
        )

        # ----------------------------------------------------
        # 8. Generate Financial Communication Passport
        # ----------------------------------------------------

        passport = (
            passport_generator.generate_from_eel(

                ledger_entry=(
                    ledger_entry
                ),

                communication_id=(
                    evidence_record.evidence_id
                ),

                communication_type=(
                    "Email / Text"
                ),

                claimed_sender=(
                    "Unknown"
                ),
            )
        )

        # ----------------------------------------------------
        # 9. API response
        # ----------------------------------------------------

        return NLPAnalysisResponse(

            label=(
                result["label"]
            ),

            class_id=(
                result["class_id"]
            ),

            confidence=(
                result["confidence"]
            ),

            confidence_percent=(
                result[
                    "confidence_percent"
                ]
            ),

            probabilities=(
                result["probabilities"]
            ),

            inference_time_ms=(
                result[
                    "inference_time_ms"
                ]
            ),

            explanation=(
                NLPExplanationResponse(

                    method=(
                        explanation[
                            "method"
                        ]
                    ),

                    predicted_class=(
                        explanation[
                            "predicted_class"
                        ]
                    ),

                    predicted_label=(
                        explanation[
                            "predicted_label"
                        ]
                    ),

                    target_class=(
                        explanation[
                            "target_class"
                        ]
                    ),

                    target_label=(
                        explanation[
                            "target_label"
                        ]
                    ),

                    target_probability=(
                        explanation[
                            "target_probability"
                        ]
                    ),

                    steps=(
                        explanation[
                            "steps"
                        ]
                    ),

                    token_count=(
                        explanation[
                            "token_count"
                        ]
                    ),

                    top_tokens=(
                        explanation[
                            "top_tokens"
                        ]
                    ),
                )
            ),

            evidence_id=(
                evidence_record.evidence_id
            ),

            ledger_id=(
                ledger_entry.ledger_id
            ),

            passport=passport,
        )

    except (TypeError, ValueError) as exc:

        logger.warning(
            "Invalid NLP prediction request: %s",
            exc,
        )

        raise HTTPException(
            status_code=(
                status.HTTP_400_BAD_REQUEST
            ),
            detail=str(exc),
        ) from exc

    except Exception as exc:

        logger.exception(
            "NLP analysis failed."
        )

        raise HTTPException(
            status_code=(
                status.HTTP_500_INTERNAL_SERVER_ERROR
            ),
            detail=(
                "NLP analysis failed."
            ),
        ) from exc