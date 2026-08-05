"""
communication_intent_analysis_service.py

Reusable Communication Intent Intelligence orchestration
service for SecureSense AI.

Pipeline:

Communication
        ↓
Communication Intent Intelligence
        ↓
Explainable Evidence Ledger
        ↓
Structured analysis result
"""

from __future__ import annotations

from typing import Any, Dict

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
    FeatureEvidence,
)

from app.eel.ledger import evidence_ledger

from app.services.communication_intent_service import (
    communication_intent_service,
)


class CommunicationIntentAnalysisService:
    """
    Reusable orchestration layer for
    Communication Intent Intelligence.
    """

    def analyse(
        self,
        text: str,
    ) -> Dict[str, Any]:

        # ----------------------------------------------------
        # 1. Intent Analysis
        # ----------------------------------------------------

        result = communication_intent_service.analyse(
            text
        )

        # ----------------------------------------------------
        # 2. Convert evidence for EEL
        # ----------------------------------------------------

        feature_evidence = [

            FeatureEvidence(

                feature=item.feature,

                value=item.description,

                contribution=item.score,

                direction=(
                    "legitimate"
                    if result.security_intent.lower()
                    in (
                        "legitimate",
                        "likely legitimate",
                    )
                    else "unknown"
                ),

                strength=item.score,

            )

            for item in result.evidence
        ]

        # ----------------------------------------------------
        # 3. Build Evidence Record
        # ----------------------------------------------------

        evidence = EvidenceRecord(

            module="Communication Intent Intelligence",

            evidence_type=(
                "COMMUNICATION_INTENT"
            ),

            input_reference=text,

            prediction=result.security_intent,

            class_id=None,

            confidence=result.confidence,

            risk_score=result.risk_score,

            explanation=feature_evidence,

            model_info=EvidenceModelInfo(

                module=(
                    "Communication Intent Intelligence"
                ),

                model_type=(
                    "Rule-based Explainable Engine"
                ),

                model_file="N/A",

                feature_count=len(
                    feature_evidence
                ),

            ),

            supporting_data={

                "context":
                    result.context,

                "context_confidence":
                    result.context_confidence,

                "security_intent":
                    result.security_intent,

                "confidence":
                    result.confidence,

                "risk_score":
                    result.risk_score,

            },

        )

        # ----------------------------------------------------
        # 4. Commit to Ledger
        # ----------------------------------------------------

        ledger_entry = evidence_ledger.record(
            evidence
        )

        # ----------------------------------------------------
        # 5. Structured Result
        # ----------------------------------------------------

        return {

            "context":
                result.context,

            "context_confidence":
                result.context_confidence,

            "security_intent":
                result.security_intent,

            "confidence":
                result.confidence,

            "risk_score":
                result.risk_score,

            "evidence":
                [
                    item.model_dump()
                    for item
                    in result.evidence
                ],

            "module":
                "Communication Intent Intelligence",

            "evidence_id":
                evidence.evidence_id,

            "ledger_id":
                ledger_entry.ledger_id,

        }


# ==========================================================
# Singleton
# ==========================================================

communication_intent_analysis_service = (
    CommunicationIntentAnalysisService()
)