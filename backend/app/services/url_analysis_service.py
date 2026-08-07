"""
url_analysis_service.py

Reusable URL Intelligence orchestration service for SecureSense AI.

Pipeline:
    URL
      ↓
    17-feature extraction
      ↓
    Frozen XGBoost phishing model
      ↓
    Native TreeSHAP explainability
      ↓
    Explainable Evidence Ledger (EEL)
      ↓
    Structured URL analysis result

This service intentionally does NOT generate a Financial
Communication Passport. The caller decides whether the URL
belongs to a standalone URL analysis or a larger multimodal
communication.
"""

from __future__ import annotations

from typing import Any, Dict

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
    FeatureEvidence,
)
from app.eel.ledger import evidence_ledger

from app.services.url_explainability_service import (
    url_explainability_service,
)
from app.services.url_model_service import (
    url_model_service,
)


class URLAnalysisService:
    """
    Reusable orchestration layer for URL phishing analysis.

    Responsibilities:
    - Run the trained XGBoost URL model
    - Generate native TreeSHAP explanations
    - Commit URL evidence to EEL
    - Return a structured result

    FCP generation is deliberately left to the caller.
    """

    # ========================================================
    # Analyse URL
    # ========================================================

    def analyse(
        self,
        url: str,
    ) -> Dict[str, Any]:
        """
        Analyse one URL and commit its explainability evidence
        to the Explainable Evidence Ledger.
        """

        # ----------------------------------------------------
        # 1. ML prediction
        # ----------------------------------------------------

        result = url_model_service.predict(
            url,
            include_features=True,
        )

        # ----------------------------------------------------
        # 2. Native TreeSHAP explainability
        # ----------------------------------------------------

        explanation = (
            url_explainability_service.explain(
                result["features"],
                top_k=5,
            )
        )
        # ----------------------------------------------------
        # 3. Convert TreeSHAP output to EEL evidence
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # 4. Build auditable EEL record
        # ----------------------------------------------------

        evidence = EvidenceRecord(
            module="URL Intelligence",

            evidence_type=(
                "URL_PHISHING_CLASSIFICATION"
            ),

            input_reference=url,

            prediction=result["label"],

            class_id=result["class_id"],

            confidence=result["confidence"],

            risk_score=result["risk_score"],

            explanation=feature_evidence,

            model_info=EvidenceModelInfo(
                module=result["model_info"]["module"],

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
                    result["phishing_probability"],

                "phishing_probability_percent":
                    result[
                        "phishing_probability_percent"
                    ],

                "legitimate_probability":
                    result["legitimate_probability"],

                "legitimate_probability_percent":
                    result[
                        "legitimate_probability_percent"
                    ],

                "features":
                    result["features"],

                "inference_time_ms":
                    result["inference_time_ms"],
            },
        )

        # ----------------------------------------------------
        # 5. Commit evidence to central ledger
        # ----------------------------------------------------

        ledger_entry = evidence_ledger.record(
            evidence
        )

        # ----------------------------------------------------
        # 6. Return reusable structured result
        # ----------------------------------------------------

        return {
            "url": url,

            "label": result["label"],

            "class_id": result["class_id"],

            "confidence": result["confidence"],

            "confidence_percent":
                result["confidence_percent"],

            "phishing_probability":
                result["phishing_probability"],

            "phishing_probability_percent":
                result[
                    "phishing_probability_percent"
                ],

            "legitimate_probability":
                result["legitimate_probability"],

            "legitimate_probability_percent":
                result[
                    "legitimate_probability_percent"
                ],

            "risk_score": result["risk_score"],

            "features": result["features"],

            "explanation": explanation,

            "model_info": result["model_info"],

            "inference_time_ms":
                result["inference_time_ms"],

            "evidence_id":
                evidence.evidence_id,

            "ledger_id":
                ledger_entry.ledger_id,

            "module":
                "URL Intelligence",
        }


# ============================================================
# Singleton
# ============================================================

url_analysis_service = URLAnalysisService()