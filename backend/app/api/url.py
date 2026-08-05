"""
url.py

SecureSense AI URL Phishing Intelligence API.

Pipeline:
    URL
      ↓
    17-feature extraction
      ↓
    Frozen XGBoost phishing model
      ↓
    Prediction + probability + risk score
      ↓
    Native TreeSHAP explainability
      ↓
    Explainable Evidence Ledger (EEL)
      ↓
    Financial Communication Passport (FCP)
"""

from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
    FeatureEvidence,
)
from app.eel.ledger import evidence_ledger

from app.fcp.generator import passport_generator
from app.fcp.models import FinancialCommunicationPassport

from app.services.url_explainability_service import (
    url_explainability_service,
)
from app.services.url_model_service import (
    url_model_service,
)
from app.services.web_content_extraction_service import (
    web_content_extraction_service,
)
from app.ai.nlp.predictor import (
    predict_email,
)


# ============================================================
# Router
# ============================================================

router = APIRouter(
    prefix="/url",
    tags=["URL Intelligence"],
)


# ============================================================
# Request / Response Schemas
# ============================================================

class URLAnalysisRequest(BaseModel):
    
    url: str = Field(
        ...,
        min_length=3,
        description="Website URL to analyse",
        examples=["https://www.google.com"],
    )

class URLBatchAnalysisRequest(BaseModel):
    urls: List[str] = Field(
        ...,
        min_length=1,
        description="List of URLs to analyse",
        examples=[
            [
                "https://google.com",
                "https://github.com",
            ]
        ],
    )

class URLExplanationItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str
    strength: float


class URLAnalysisResponse(BaseModel):
    
    url: str

    label: str
    class_id: int

    confidence: float
    confidence_percent: float

    phishing_probability: float
    phishing_probability_percent: float

    legitimate_probability: float
    legitimate_probability_percent: float

    risk_score: float

    features: Dict[str, Any]

    explanation: List[URLExplanationItem]

    model_info: Dict[str, Any]

    inference_time_ms: float

    web_content: Dict[str, Any]

    web_content_nlp: Dict[str, Any] | None = None

    # --------------------------------------------------------
    # Explainable Evidence Ledger
    # --------------------------------------------------------

    evidence_id: str
    ledger_id: str
    # --------------------------------------------------------
    # Financial Communication Passport
    # --------------------------------------------------------

    passport: FinancialCommunicationPassport

class URLBatchAnalysisResponse(BaseModel):
    count: int
    results: List[URLAnalysisResponse]

# ============================================================
# Analyse URL
# ============================================================

@router.post(
    "/analyse",
    response_model=URLAnalysisResponse,
)
def analyse_url(
    request: URLAnalysisRequest,
):
    """
    Analyse a URL using the frozen SecureSense 17-feature
    XGBoost phishing model, generate native TreeSHAP evidence,
    record the evidence in EEL and generate an FCP.
    """

    try:

        # ====================================================
        # 1. ML Prediction
        # ====================================================

        result = url_model_service.predict(
            request.url,
            include_features=True,
        )
        from app.services.domain_verification_service import (
            domain_verification_service,
        )

        domain_info = (
            domain_verification_service.verify(
                request.url
            )
        )

        web_content = (
            web_content_extraction_service.extract(
                request.url
            )
        )

        # ====================================================
# Web Content NLP Analysis
# ====================================================

        nlp_result = None
        if (
            web_content["success"]
            and web_content["character_count"] >= 50
        ):
            try:
                nlp_result = predict_email(
                    web_content["text"]
                )
            except Exception:
                nlp_result = None
        # ====================================================
        # 2. Native TreeSHAP Explainability
        # ====================================================

        explanation = (
            url_explainability_service.explain(
                result["features"],
                top_k=5,
            )
        )

        # ====================================================
        # 3. Convert Explainability Output to EEL Evidence
        # ====================================================

        feature_evidence = [
            FeatureEvidence(
                feature=item["feature"],
                value=item["value"],
                contribution=item["shap_value"],
                direction=item["direction"],
                strength=item["strength"],
            )
            for item in explanation
        ]

        # ====================================================
        # 4. Build Auditable Evidence Record
        # ====================================================

        evidence = EvidenceRecord(
            module="URL Intelligence",

            evidence_type=(
                "URL_PHISHING_CLASSIFICATION"
            ),

            input_reference=request.url,

            prediction=result["label"],

            class_id=result["class_id"],

            confidence=result["confidence"],

            risk_score=result["risk_score"],

            explanation=feature_evidence,

            model_info=EvidenceModelInfo(
                module=(
                    result["model_info"]["module"]
                ),

                model_type=(
                    result["model_info"]["model_type"]
                ),

                model_file=(
                    result["model_info"]["model_file"]
                ),

                feature_count=(
                    result["model_info"]["feature_count"]
                ),
            ),

            supporting_data={
                "phishing_probability":
                    result[
                        "phishing_probability"
                    ],

                "phishing_probability_percent":
                    result[
                        "phishing_probability_percent"
                    ],

                "legitimate_probability":
                    result[
                        "legitimate_probability"
                    ],

                "legitimate_probability_percent":
                    result[
                        "legitimate_probability_percent"
                    ],

                "features":
                    result["features"],

                "inference_time_ms":
                    result[
                        "inference_time_ms"
                    ],
            },
        )

        # ====================================================
        # 5. Commit Evidence to EEL
        # ====================================================

        ledger_entry = evidence_ledger.record(
            evidence
        )

        # ====================================================
        # 6. Generate Financial Communication Passport
        # ====================================================

        passport = (
            passport_generator.generate_from_eel(
                ledger_entry=ledger_entry,

                communication_id=(
                    evidence.evidence_id
                ),

                communication_type="URL",

                claimed_sender="Unknown",
            )
        )

        passport.verification.official_domain = (
            domain_info["official_domain"]
        )

        passport.verification.official_provider = (
            domain_info["provider"]
        )

        passport.verification.registered_domain = (
            domain_info["registered_domain"]
        )

        # ====================================================
        # 7. Unified API Response
        # ====================================================

        return URLAnalysisResponse(
            url=request.url,

            label=result["label"],

            class_id=result["class_id"],

            confidence=result["confidence"],

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

            risk_score=result["risk_score"],

            features=result["features"],

            explanation=explanation,

            model_info=result["model_info"],

            inference_time_ms=result[
                "inference_time_ms"
            ],

            web_content=web_content,


            web_content_nlp=nlp_result,
            
            evidence_id=(
                evidence.evidence_id
            ),

            ledger_id=(
                ledger_entry.ledger_id
            ),

            domain_verification=domain_info,

            passport=passport,
        )
    

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                f"URL analysis failed: {str(exc)}"
            ),
        ) from exc


@router.post(
    "/analyse-batch",
    response_model=URLBatchAnalysisResponse,
)
def analyse_urls(
    request: URLBatchAnalysisRequest,
):
    """
    Analyse multiple URLs in one request.
    Useful for benchmarking and regression testing.
    """

    results = []

    for url in request.urls:

        single_result = analyse_url(
            URLAnalysisRequest(
                url=url,
            )
        )

        results.append(single_result)

    return URLBatchAnalysisResponse(
        count=len(results),
        results=results,
    )