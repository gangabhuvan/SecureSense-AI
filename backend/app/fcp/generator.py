"""
generator.py

Generates the SecureSense AI Financial Communication
Passport (FCP).

The generator does NOT perform threat detection.
It converts intelligence/evidence from SecureSense modules
into a standardized trust passport.

Supported EEL sources:
    - URL Intelligence / TreeSHAP
    - Visual Phishing Intelligence / Grad-CAM
    - NLP Security Analysis / Integrated Gradients
"""

from datetime import datetime, timezone
from uuid import uuid4

from app.models.analysis_models import AnalysisResult

from app.models.voice_models import (
    VoiceAuthenticityResult,
)

from app.eel.evidence_models import (
    EvidenceLedgerEntry,
)

from app.fcp.models import (
    EvidenceSummary,
    ExplainableEvidenceItem,
    FinancialCommunicationPassport,
    VerificationStatus,
)

from app.fcp.calculators import (
    build_evidence_summary,
    calculate_trust_score,
    get_recommended_action,
)


class PassportGenerator:
    """
    Generates Financial Communication Passports from either
    generic/hybrid AnalysisResult objects or committed EEL
    evidence.
    """

    # ========================================================
    # Helpers
    # ========================================================

    @staticmethod
    def _passport_id() -> str:

        year = datetime.now(
            timezone.utc
        ).year

        return (
            f"FCP-{year}-"
            f"{uuid4().hex[:6].upper()}"
        )

    @staticmethod
    def _risk_level(
        risk_score: float,
    ) -> str:

        if risk_score >= 70:
            return "High"

        if risk_score >= 40:
            return "Medium"

        return "Low"

    @staticmethod
    def _threat_categories(
        prediction: str,
    ) -> list[str]:
        """
        Convert an intelligence-module prediction into
        standardized FCP threat categories.
        """

        prediction_normalized = (
            prediction.strip().lower()
        )

        categories: list[str] = []

        if prediction_normalized == "phishing":

            categories.append(
                "Phishing"
            )

        elif prediction_normalized == "spam":

            categories.append(
                "Spam"
            )

        return categories

    # ========================================================
    # Hybrid AnalysisResult Evidence Summary
    # ========================================================

    @staticmethod
    def _build_hybrid_evidence_summary(
        analysis: AnalysisResult,
    ) -> EvidenceSummary:
        """
        Build the evidence summary for the hybrid document
        analysis pipeline.

        Preserves the existing rule-based evidence summary
        while attaching references to evidence already
        committed to the Explainable Evidence Ledger.
        """

        summary = build_evidence_summary(
            analysis
        )

        # ----------------------------------------------------
        # EEL evidence IDs
        # ----------------------------------------------------

        summary.evidence_ids = list(
            dict.fromkeys(
                analysis.evidence_ids
            )
        )

        # ----------------------------------------------------
        # EEL ledger IDs
        # ----------------------------------------------------

        summary.ledger_ids = list(
            dict.fromkeys(
                analysis.ledger_ids
            )
        )

        # ----------------------------------------------------
        # Intelligence modules that generated EEL evidence
        # ----------------------------------------------------

        summary.modules = list(
            dict.fromkeys(
                analysis.evidence_modules
            )
        )

        return summary

    # ========================================================
    # Generic / Hybrid AnalysisResult → FCP
    # ========================================================

    def generate(
        self,
        analysis: AnalysisResult,
        communication_id: str | None = None,
        communication_type: str = "Unknown",
        claimed_sender: str = "Unknown",
        voice_authenticity: (
            VoiceAuthenticityResult | None
        ) = None,
    ) -> FinancialCommunicationPassport:

        # ----------------------------------------------------
        # Threat categories from rule findings
        # ----------------------------------------------------

        threat_categories = sorted(
            {
                finding.category
                for finding in analysis.findings
            }
        )

        # ----------------------------------------------------
        # Also preserve NLP threat classification when present
        # ----------------------------------------------------

        if analysis.nlp is not None:

            nlp_categories = (
                self._threat_categories(
                    analysis.nlp.label
                )
            )

            threat_categories = sorted(
                set(
                    threat_categories
                    + nlp_categories
                )
            )

        # ----------------------------------------------------
        # Hybrid evidence summary
        # ----------------------------------------------------

        evidence_summary = (
            self._build_hybrid_evidence_summary(
                analysis
            )
        )

        ai_manipulation_findings = []
        if (
            voice_authenticity is not None
            and voice_authenticity.available
        ):
            if (
                voice_authenticity.prediction.lower()
                == "synthetic"
            ):
                ai_manipulation_findings.append(
                    (
                        "Synthetic voice detected "
                        f"using Spectra-AASIST3 "
                        f"({voice_authenticity.confidence_percent:.2f}% "
                        "confidence)."
                    )
                )

            else:
                ai_manipulation_findings.append(
                    (
                        "No evidence of synthetic speech "
                        "was detected by Spectra-AASIST3."
                    )
                )

        # ----------------------------------------------------
        # Passport
        # ----------------------------------------------------

        return FinancialCommunicationPassport(

            passport_id=(
                self._passport_id()
            ),

            communication_id=(
                communication_id
            ),

            communication_type=(
                communication_type
            ),

            claimed_sender=(
                claimed_sender
            ),

            # TrustService attaches the real AVE result
            # after passport generation.
            verified_sender=False,

            verification=(
                VerificationStatus(
                    status="Not Performed"
                )
            ),

            threat_categories=(
                threat_categories
            ),

            ai_manipulation_findings=(
                ai_manipulation_findings
            ),

            risk_score=(
                analysis.risk_score
            ),

            risk_level=(
                analysis.risk_level
            ),

            trust_score=(
                calculate_trust_score(
                    analysis.risk_score
                )
            ),

            confidence=(
                analysis.confidence
            ),

            evidence=(
                evidence_summary
            ),

            recommended_action=(
                get_recommended_action(
                    analysis.risk_level
                )
            ),
        )

    # ========================================================
    # EEL Feature Explainability
    # ========================================================

    @staticmethod
    def _feature_explanations(
        ledger_entry: EvidenceLedgerEntry,
    ) -> list[ExplainableEvidenceItem]:
        """
        Convert feature-based EEL evidence such as URL
        TreeSHAP into FCP explainability items.
        """

        evidence = (
            ledger_entry.evidence
        )

        return [

            ExplainableEvidenceItem(

                source_module=(
                    evidence.module
                ),

                feature=item.feature,

                value=item.value,

                contribution=(
                    item.contribution
                ),

                direction=item.direction,

                strength=item.strength,
            )

            for item in evidence.explanation
        ]

    # ========================================================
    # EEL Visual Explainability
    # ========================================================

    @staticmethod
    def _visual_explanations(
        ledger_entry: EvidenceLedgerEntry,
    ) -> list[ExplainableEvidenceItem]:
        """
        Convert compact Grad-CAM evidence into FCP
        explainability items.
        """

        evidence = (
            ledger_entry.evidence
        )

        visual = (
            evidence.visual_explanation
        )

        if visual is None:

            return []

        hotspot = (
            visual.max_attention_point
        )

        attention_item = (
            ExplainableEvidenceItem(

                source_module=(
                    evidence.module
                ),

                feature=(
                    "gradcam_max_attention"
                ),

                value=(
                    visual.max_attention
                ),

                contribution=(
                    visual.max_attention
                ),

                direction=(
                    visual.target_label.lower()
                ),

                strength=(
                    visual.max_attention
                ),
            )
        )

        attention_ratio_item = (
            ExplainableEvidenceItem(

                source_module=(
                    evidence.module
                ),

                feature=(
                    "gradcam_high_attention_ratio"
                ),

                value=(
                    visual.high_attention_ratio
                ),

                contribution=(
                    visual.high_attention_ratio
                ),

                direction=(
                    visual.target_label.lower()
                ),

                strength=(
                    visual.high_attention_ratio
                ),
            )
        )

        hotspot_item = (
            ExplainableEvidenceItem(

                source_module=(
                    evidence.module
                ),

                feature=(
                    "gradcam_attention_hotspot"
                ),

                value={
                    "x": hotspot.x,
                    "y": hotspot.y,

                    "x_normalized":
                        hotspot.x_normalized,

                    "y_normalized":
                        hotspot.y_normalized,

                    "image_width":
                        visual.image_width,

                    "image_height":
                        visual.image_height,

                    "target_class":
                        visual.target_class,

                    "target_label":
                        visual.target_label,

                    "target_probability":
                        visual.target_probability,

                    "method":
                        visual.method,

                    "target_layer":
                        visual.target_layer,
                },

                contribution=0.0,

                direction=(
                    visual.target_label.lower()
                ),

                strength=0.0,
            )
        )

        return [
            attention_item,
            attention_ratio_item,
            hotspot_item,
        ]

    # ========================================================
    # EEL NLP Explainability
    # ========================================================

    @staticmethod
    def _nlp_explanations(
        ledger_entry: EvidenceLedgerEntry,
    ) -> list[ExplainableEvidenceItem]:
        """
        Convert DistilBERT Integrated Gradients token
        attribution into FCP explainability items.
        """

        evidence = (
            ledger_entry.evidence
        )

        nlp = (
            evidence.nlp_explanation
        )

        if nlp is None:

            return []

        items: list[
            ExplainableEvidenceItem
        ] = []

        for token in nlp.top_tokens:

            items.append(
                ExplainableEvidenceItem(

                    source_module=(
                        evidence.module
                    ),

                    feature=(
                        "token_attribution"
                    ),

                    value={
                        "token":
                            token.token,

                        "token_index":
                            token.token_index,

                        "target_class":
                            nlp.target_class,

                        "target_label":
                            nlp.target_label,

                        "target_probability":
                            nlp.target_probability,

                        "method":
                            nlp.method,

                        "steps":
                            nlp.steps,

                        "normalized_strength":
                            token.normalized_strength,
                    },

                    contribution=(
                        token.attribution
                    ),

                    direction=(
                        token.direction
                    ),

                    strength=(
                        token.strength
                    ),
                )
            )

        return items

    # ========================================================
    # Combined Explainability
    # ========================================================

    def _explainable_evidence(
        self,
        ledger_entry: EvidenceLedgerEntry,
    ) -> list[ExplainableEvidenceItem]:
        """
        Build FCP explainability from every explanation type
        attached to an EEL record.
        """

        items: list[
            ExplainableEvidenceItem
        ] = []

        # URL / generic feature evidence
        items.extend(
            self._feature_explanations(
                ledger_entry
            )
        )

        # Visual / Grad-CAM
        items.extend(
            self._visual_explanations(
                ledger_entry
            )
        )

        # NLP / Integrated Gradients
        items.extend(
            self._nlp_explanations(
                ledger_entry
            )
        )

        return items

    # ========================================================
    # Real EEL → FCP path
    # ========================================================

    def generate_from_eel(
        self,
        ledger_entry: EvidenceLedgerEntry,
        communication_id: str | None = None,
        communication_type: str = "Unknown",
        claimed_sender: str = "Unknown",
    ) -> FinancialCommunicationPassport:

        evidence = (
            ledger_entry.evidence
        )

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        risk_score = float(
            evidence.risk_score
        )

        risk_level = (
            self._risk_level(
                risk_score
            )
        )

        # ----------------------------------------------------
        # Threat categories
        # ----------------------------------------------------

        threat_categories = (
            self._threat_categories(
                evidence.prediction
            )
        )

        # ----------------------------------------------------
        # Explainability
        # ----------------------------------------------------

        explainable_evidence = (
            self._explainable_evidence(
                ledger_entry
            )
        )

        # ----------------------------------------------------
        # Evidence summary
        # ----------------------------------------------------

        evidence_summary = EvidenceSummary(

            total_findings=len(
                explainable_evidence
            ),

            evidence_ids=[
                evidence.evidence_id
            ],

            ledger_ids=[
                ledger_entry.ledger_id
            ],

            modules=[
                evidence.module
            ],
        )

        # ----------------------------------------------------
        # AI manipulation
        # ----------------------------------------------------

        ai_manipulation_findings = []

        # ----------------------------------------------------
        # Verification
        #
        # Standalone EEL-generated passports have not passed
        # through TrustService / AVE.
        # ----------------------------------------------------

        verification = (
            VerificationStatus(
                status="Not Performed"
            )
        )

        # ----------------------------------------------------
        # Passport
        # ----------------------------------------------------

        return FinancialCommunicationPassport(

            passport_id=(
                self._passport_id()
            ),

            communication_id=(
                communication_id
                or evidence.evidence_id
            ),

            communication_type=(
                communication_type
            ),

            claimed_sender=(
                claimed_sender
            ),

            verified_sender=False,

            verification=verification,

            threat_categories=(
                threat_categories
            ),

            ai_manipulation_findings=(
                ai_manipulation_findings
            ),

            risk_score=(
                risk_score
            ),

            risk_level=(
                risk_level
            ),

            trust_score=(
                calculate_trust_score(
                    risk_score
                )
            
            ),

            confidence=float(
                evidence.confidence
            ),

            evidence=(
                evidence_summary
            ),

            explainable_evidence=(
                explainable_evidence
            ),

            recommended_action=(
                get_recommended_action(
                    risk_level
                )
            ),
        )


# ============================================================
# Singleton
# ============================================================

passport_generator = PassportGenerator()