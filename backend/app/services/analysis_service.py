"""
analysis_service.py

Orchestrates the complete SecureSense AI fraud detection pipeline.

Pipeline:
    OCR Text
        ↓
    ┌──────────────────────────────────────┐
    │                                      │
    ↓                                      ↓
Entity / Rule Analysis              DistilBERT NLP
                                           ↓
                                  Integrated Gradients
                                           ↓
                               Explainable Evidence Ledger
    │                                      │
    └──────────────────┬───────────────────┘
                       ↓
               Hybrid Risk Scoring
                       ↓
            Trust Layer / AVE / FCP
                       ↓
              Final Analysis Result
"""

from __future__ import annotations

import logging

from app.ai.nlp.predictor import predict_email
from app.services.communication_selector import (
    communication_selector,
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

from app.models.analysis_models import (
    AnalysisResult,
    NLPResult,
)

from app.services.context_detector import (
    context_detector,
)

from app.services.entity_extractor import (
    entity_extractor,
)

from app.services.nlp_explainability_service import (
    nlp_explainability_service,
)

from app.services.rule_engine import (
    rule_engine,
)

from app.services.scoring_engine import (
    scoring_engine,
)

from app.services.trust_service import (
    trust_service,
)


logger = logging.getLogger(__name__)


# ==========================================================
# Analysis Service
# ==========================================================

class AnalysisService:
    """
    Main orchestration service for SecureSense AI analysis.

    Combines:
    - Entity extraction
    - Context detection
    - Rule-based fraud detection
    - DistilBERT NLP classification
    - Integrated Gradients explainability
    - Explainable Evidence Ledger
    - Hybrid risk scoring
    - Authenticity verification
    - Financial Communication Passport generation
    """

    # ======================================================
    # NLP Risk
    # ======================================================

    @staticmethod
    def _calculate_nlp_risk(
        probabilities: dict,
    ) -> float:
        """
        Convert DistilBERT class probabilities into the
        SecureSense 0-100 NLP risk scale.

        Predictor probabilities are percentages.

        Phishing receives full risk weight.
        Spam receives partial risk weight.
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

    # ======================================================
    # NLP Analysis
    # ======================================================

    def _analyse_nlp(
        self,
        text: str,
    ) -> NLPResult:
        """
        Run the frozen DistilBERT classifier.
        """

        # ----------------------------------------------
        # Select only reader-directed communication
        # for DistilBERT.
        # ----------------------------------------------

        communication_text = (
            communication_selector.select(
                text
            )
        )
        print("\n========== SELECTED COMMUNICATION ==========")
        print(communication_text)
        print("===========================================\n")

        # Never send an empty string to DistilBERT.
        # If nothing meaningful was selected,
        # gracefully fall back to the original text.
        if not communication_text.strip():
            communication_text = text
        print("\n========== TEXT SENT TO DISTILBERT ==========")
        print(communication_text)
        print("=============================================\n")
        prediction = predict_email(
            communication_text
        )
        print("\n========== DISTILBERT OUTPUT ==========")
        print("Label:", prediction["label"])
        print("Confidence:", prediction["confidence_percent"])
        print("Probabilities:", prediction["probabilities"])
        print("=======================================\n")


        nlp_risk = (
            self._calculate_nlp_risk(
                prediction[
                    "probabilities"
                ]
            )
        )

        return NLPResult(

            label=(
                prediction["label"]
            ),

            class_id=(
                prediction["class_id"]
            ),

            confidence=(
                prediction["confidence"]
            ),

            confidence_percent=(
                prediction[
                    "confidence_percent"
                ]
            ),

            probabilities=(
                prediction[
                    "probabilities"
                ]
            ),

            inference_time_ms=(
                prediction[
                    "inference_time_ms"
                ]
            ),

            risk_score=nlp_risk,
            communication_text=communication_text,
        )

    # ======================================================
    # NLP Explainability + EEL
    # ======================================================

    def _record_nlp_evidence(
        self,
        text: str,
        nlp_result: NLPResult,
    ):
        """
        Generate Integrated Gradients evidence for the
        DistilBERT decision and commit it to the central EEL.

        Returns
        -------
        EvidenceLedgerEntry
            The committed ledger entry.
        """

        # --------------------------------------------------
        # Integrated Gradients
        # --------------------------------------------------

        explanation = (
            nlp_explainability_service.explain(
                text,
                target_class=(
                    nlp_result.class_id
                ),
                top_k=10,
            )
        )

        # --------------------------------------------------
        # Consistency validation
        # --------------------------------------------------

        if (
            explanation[
                "predicted_class"
            ]
            != nlp_result.class_id
        ):

            raise RuntimeError(
                "NLP prediction/explanation "
                "class mismatch."
            )

        if (
            explanation[
                "predicted_label"
            ]
            != nlp_result.label
        ):

            raise RuntimeError(
                "NLP prediction/explanation "
                "label mismatch."
            )

        # --------------------------------------------------
        # Token evidence
        # --------------------------------------------------

        token_evidence = [

            TokenEvidence(

                token=item[
                    "token"
                ],

                token_index=item[
                    "token_index"
                ],

                attribution=item[
                    "attribution"
                ],

                strength=item[
                    "strength"
                ],

                normalized_strength=item[
                    "normalized_strength"
                ],

                direction=item[
                    "direction"
                ],
            )

            for item
            in explanation[
                "top_tokens"
            ]
        ]

        # --------------------------------------------------
        # NLP explanation object
        # --------------------------------------------------

        nlp_explanation = (
            NLPExplanationEvidence(

                method=explanation[
                    "method"
                ],

                target_class=explanation[
                    "target_class"
                ],

                target_label=explanation[
                    "target_label"
                ],

                target_probability=(
                    explanation[
                        "target_probability"
                    ]
                ),

                steps=explanation[
                    "steps"
                ],

                token_count=explanation[
                    "token_count"
                ],

                top_tokens=(
                    token_evidence
                ),
            )
        )

        # --------------------------------------------------
        # EEL record
        # --------------------------------------------------

        evidence_record = (
            EvidenceRecord(

                module=(
                    "NLP Security Analysis"
                ),

                evidence_type=(
                    "nlp_integrated_gradients"
                ),

                prediction=(
                    nlp_result.label
                ),

                class_id=(
                    nlp_result.class_id
                ),

                confidence=(
                    nlp_result.confidence
                ),

                risk_score=(
                    nlp_result.risk_score
                ),

                nlp_explanation=(
                    nlp_explanation
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

                    "communication_text":
                        nlp_result.communication_text,

                    "probabilities":
                        nlp_result.probabilities,

                    "inference_time_ms":
                        nlp_result.inference_time_ms,

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

        # --------------------------------------------------
        # Commit to central ledger
        # --------------------------------------------------

        return evidence_ledger.record(
            evidence_record
        )

    # ======================================================
    # Main Analysis
    # ======================================================

    def analyse(
        self,
        text: str,
    ) -> AnalysisResult:
        """
        Analyse OCR-extracted text using the complete
        SecureSense hybrid fraud detection pipeline.
        """

        # --------------------------------------------------
        # Validate input
        # --------------------------------------------------

        if not isinstance(
            text,
            str,
        ):
            raise TypeError(
                "Analysis input must be a string."
            )

        text = text.strip()

        # --------------------------------------------------
        # Empty OCR result
        # --------------------------------------------------

        if not text:

            logger.warning(
                "Analysis received empty OCR text."
            )

            empty_context = (
                context_detector.detect("")
            )

            result = scoring_engine.score(
                findings=[],
                context=empty_context,
                entities={},
                nlp=None,
            )

            result.summary = (
                "No analysable text content was available. "
                "A reliable communication-level security assessment "
                "could not be produced from text."
            )

            result.confidence = round(
                result.confidence,
                2,
            )

            result.document_confidence = round(
                result.document_confidence,
                2,
            )

            result.passport = (
                trust_service.process(
                    analysis=result,
                    communication_type=(
                        result.document_type
                    ),
                    analysis_available=False,
                )
            )

            return result

        # --------------------------------------------------
        # Step 1: Entity extraction
        # --------------------------------------------------

        entities = (
            entity_extractor.extract(
                text
            )
        )

        # --------------------------------------------------
        # Step 2: Context detection
        # --------------------------------------------------

        context = (
            context_detector.detect(
                text
            )
        )

        # --------------------------------------------------
        # Step 3: Explainable rules
        # --------------------------------------------------

        findings = (
            rule_engine.evaluate(
                text=text,
                entities=entities,
                context=context,
            )
        )

        # --------------------------------------------------
        # Step 4: DistilBERT classification
        # --------------------------------------------------

        nlp_result = None
        nlp_ledger_entry = None

        try:

            nlp_result = (
                self._analyse_nlp(
                    text
                )
            )

            logger.info(
                (
                    "NLP classification: %s | "
                    "confidence=%.4f | "
                    "risk=%.4f"
                ),
                nlp_result.label,
                nlp_result.confidence,
                nlp_result.risk_score,
            )

            # ----------------------------------------------
            # Step 5: Integrated Gradients + EEL
            # ----------------------------------------------

            try:

                nlp_ledger_entry = (
                    self._record_nlp_evidence(
                        text=nlp_result.communication_text,
                        nlp_result=nlp_result,
                    )
                )

                logger.info(
                    (
                        "NLP evidence committed: "
                        "%s | %s"
                    ),
                    (
                        nlp_ledger_entry
                        .evidence
                        .evidence_id
                    ),
                    (
                        nlp_ledger_entry
                        .ledger_id
                    ),
                )

            except Exception:

                # Explainability/EEL failure should not
                # discard a valid DistilBERT prediction.

                logger.exception(
                    "NLP explainability/EEL "
                    "generation failed. "
                    "Continuing with NLP "
                    "classification."
                )

                nlp_ledger_entry = None

        except Exception:

            # A model failure should not make the complete
            # document pipeline unavailable.

            logger.exception(
                "DistilBERT NLP analysis failed. "
                "Continuing with rule-based "
                "analysis."
            )

            nlp_result = None
            nlp_ledger_entry = None

        # --------------------------------------------------
        # Step 6: Hybrid risk scoring
        # --------------------------------------------------

        result = (
            scoring_engine.score(
                findings=findings,
                context=context,
                entities=(
                    entities.as_dict()
                ),
                nlp=nlp_result,
            )
        )

        # --------------------------------------------------
        # Step 7: Attach EEL references
        # --------------------------------------------------

        if (
            nlp_ledger_entry
            is not None
        ):

            result.evidence_ids.append(
                nlp_ledger_entry
                .evidence
                .evidence_id
            )

            result.ledger_ids.append(
                nlp_ledger_entry
                .ledger_id
            )

            result.evidence_modules.append(
                nlp_ledger_entry
                .evidence
                .module
            )

        # --------------------------------------------------
        # Step 8: Standardize confidence
        # --------------------------------------------------

        result.confidence = round(
            result.confidence,
            2,
        )

        result.document_confidence = round(
            result.document_confidence,
            2,
        )

        # --------------------------------------------------
        # Step 9: Trust Layer
        #
        # AVE + final hybrid FCP.
        # --------------------------------------------------

        result.passport = (
            trust_service.process(
                analysis=result,
                communication_type=(
                    result.document_type
                ),
            )
        )

        return result


# ==========================================================
# Singleton
# ==========================================================

analysis_service = AnalysisService()