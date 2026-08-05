"""
scoring_engine.py

ML-first risk scoring engine for SecureSense AI.

Principles
----------
- Trained ML probabilities remain authoritative.
- Rule-based findings provide additional deterministic evidence.
- Rule evidence may increase risk, but must not dilute a stronger
  trained-model threat signal.
- Model confidence is preserved rather than reduced by arbitrary
  hand-written fusion weights.
"""

from __future__ import annotations

from typing import List, Optional

from app.models.analysis_models import (
    AnalysisResult,
    DocumentContext,
    Finding,
    NLPResult,
)


# ==========================================================
# Scoring Engine
# ==========================================================

class ScoringEngine:
    """
    Calculates the SecureSense risk assessment.

    Current document pipeline:

        Rule Engine ───────┐
                           ├── Risk Assessment
        DistilBERT NLP ────┘

    The DistilBERT probability is preserved as the learned
    phishing signal. Rule-based evidence can increase the
    resulting risk but cannot reduce the ML-derived risk.
    """

    def __init__(self) -> None:

        self.severity_weights = {
            "High": 20,
            "Medium": 12,
            "Low": 5,
        }

        # Spam is not equivalent to phishing.
        # It is retained as a separate, lower-risk category.
        self.spam_risk_factor = 0.45

    # ======================================================
    # Duplicate Removal
    # ======================================================

    def remove_duplicates(
        self,
        findings: List[Finding],
    ) -> List[Finding]:

        unique = {}

        for finding in findings:

            key = (
                finding.category.lower(),
                finding.matched_text.lower(),
            )

            if key not in unique:
                unique[key] = finding

        return list(unique.values())

    # ======================================================
    # Rule Score
    # ======================================================

    def calculate_rule_score(
        self,
        findings: List[Finding],
    ) -> int:
        """
        Calculate deterministic rule-based risk.

        This score is an independent evidence signal.
        It is NOT averaged with the trained ML probability.
        """

        score = sum(
            finding.score
            for finding in findings
        )

        return min(
            max(int(score), 0),
            100,
        )

    # ======================================================
    # NLP Risk
    # ======================================================

    def calculate_nlp_risk(
        self,
        nlp: Optional[NLPResult],
    ) -> float:
        """
        Derive security risk directly from trained DistilBERT
        class probabilities.

        Phishing probability maps directly to phishing risk.

        Spam contributes a smaller risk signal because spam
        does not necessarily imply credential or financial
        compromise.
        """

        if nlp is None:
            return 0.0

        phishing_probability = float(
            nlp.probabilities.get(
                "Phishing",
                0.0,
            )
        )

        spam_probability = float(
            nlp.probabilities.get(
                "Spam",
                0.0,
            )
        )

        phishing_risk = phishing_probability

        spam_risk = (
            spam_probability
            * self.spam_risk_factor
        )

        # Preserve the strongest learned security signal.
        risk = max(
            phishing_risk,
            spam_risk,
        )

        return round(
            min(
                max(risk, 0.0),
                100.0,
            ),
            2,
        )

    # ======================================================
    # Final Risk Score
    # ======================================================

    def calculate_final_score(
        self,
        findings: List[Finding],
        nlp: Optional[NLPResult],
    ) -> int:
        """
        Calculate final risk without diluting ML predictions.

        When NLP is available:

            final risk = max(
                ML-derived risk,
                deterministic rule risk
            )

        Therefore a 99.99% phishing prediction cannot become
        40%, 65%, or 80% merely because the rule engine found
        fewer indicators.

        When NLP is unavailable, the rule engine provides the
        fallback risk assessment.
        """

        rule_score = self.calculate_rule_score(
            findings
        )

        if nlp is None:
            return rule_score

        nlp_risk = self.calculate_nlp_risk(
            nlp
        )

        nlp.risk_score = nlp_risk

        final_score = max(
            float(rule_score),
            nlp_risk,
        )

        return int(
            round(
                min(
                    max(final_score, 0.0),
                    100.0,
                )
            )
        )

    # ======================================================
    # Risk Level
    # ======================================================

    @staticmethod
    def calculate_risk_level(
        score: int,
    ) -> str:

        if score >= 75:
            return "High"

        if score >= 40:
            return "Medium"

        return "Low"

    # ======================================================
    # Rule Confidence
    # ======================================================

    def calculate_rule_confidence(
        self,
        findings: List[Finding],
        context: DocumentContext,
    ) -> float:
        """
        Confidence available from the deterministic analysis
        path when the NLP model is unavailable.
        """

        if not findings:
            return float(
                context.confidence
            )

        severity_score = sum(
            self.severity_weights.get(
                finding.severity,
                0,
            )
            for finding in findings
        )

        severity_score = min(
            severity_score,
            100,
        )

        confidence = max(
            float(severity_score),
            float(context.confidence),
        )

        return round(
            min(
                max(confidence, 0.0),
                100.0,
            ),
            2,
        )

    # ======================================================
    # Final Confidence
    # ======================================================

    def calculate_final_confidence(
        self,
        findings: List[Finding],
        context: DocumentContext,
        nlp: Optional[NLPResult],
    ) -> float:
        """
        Preserve trained-model confidence when NLP inference
        succeeds.

        Rule/context confidence is used only as the fallback
        when the ML model is unavailable.
        """

        if nlp is not None:

            return round(
                min(
                    max(
                        float(
                            nlp.confidence_percent
                        ),
                        0.0,
                    ),
                    100.0,
                ),
                2,
            )

        return self.calculate_rule_confidence(
            findings,
            context,
        )

    # ======================================================
    # Grammar Helper
    # ======================================================

    @staticmethod
    def get_article(
        word: str,
    ) -> str:

        if not word:
            return "a"

        return (
            "an"
            if word[:1].lower() in "aeiou"
            else "a"
        )

    # ======================================================
    # Summary
    # ======================================================

    def generate_summary(
        self,
        findings: List[Finding],
        risk_level: str,
        context: DocumentContext,
        nlp: Optional[NLPResult],
    ) -> str:

        document_type = (
            context.document_type
            or "Unknown"
        )

        categories = []

        for finding in findings:

            if finding.category not in categories:
                categories.append(
                    finding.category
                )

        detected = ", ".join(
            categories
        )

        # --------------------------------------------------
        # Phishing
        # --------------------------------------------------

        if (
            nlp is not None
            and nlp.label.lower() == "phishing"
        ):

            if findings:

                return (
                    f"This {document_type.lower()} communication "
                    "was classified as phishing by the trained "
                    "NLP security model and contains additional "
                    "rule-based suspicious indicators"
                    + (
                        f" including {detected}."
                        if detected
                        else "."
                    )
                    + " Do not follow links, transfer money, "
                    "or share sensitive information until the "
                    "sender has been independently verified."
                )

            return (
                f"This {document_type.lower()} communication "
                "was classified as phishing by the trained NLP "
                "security model. Independently verify the sender "
                "before following links, transferring money, or "
                "sharing sensitive information."
            )

        # --------------------------------------------------
        # Spam
        # --------------------------------------------------

        if (
            nlp is not None
            and nlp.label.lower() == "spam"
        ):

            return (
                f"This {document_type.lower()} communication "
                "was classified as spam by the trained NLP "
                "security model. Treat unsolicited links and "
                "requests with caution."
            )

        # --------------------------------------------------
        # Rule-based high/medium risk
        # --------------------------------------------------

        if findings and risk_level == "High":

            return (
                f"This {document_type.lower()} communication "
                "contains high-risk fraud indicators"
                + (
                    f" including {detected}."
                    if detected
                    else "."
                )
                + " Independently verify the communication "
                "before taking financial or sensitive action."
            )

        if findings and risk_level == "Medium":

            return (
                f"This {document_type.lower()} communication "
                "contains suspicious indicators"
                + (
                    f" including {detected}."
                    if detected
                    else "."
                )
                + " Proceed with caution and independently "
                "verify the communication before taking action."
            )

        # --------------------------------------------------
        # Legitimate / Low risk
        # --------------------------------------------------

        article = self.get_article(
            document_type
        )

        if (
            nlp is not None
            and nlp.label.lower() == "legitimate"
            and not findings
        ):

            return (
                f"This appears to be {article} "
                f"{document_type.lower()} communication. "
                "No significant rule-based fraud indicators "
                "were detected, and the trained NLP security "
                "model classified the content as legitimate."
            )

        if not findings:

            return (
                f"This appears to be {article} "
                f"{document_type.lower()} communication. "
                "No significant fraud indicators were detected."
            )

        return (
            f"This appears to be {article} "
            f"{document_type.lower()} communication. "
            f"Minor indicators were detected ({detected}). "
            "Exercise normal caution."
        )

    # ======================================================
    # Main Scoring API
    # ======================================================

    def score(
        self,
        findings: List[Finding],
        context: DocumentContext,
        entities: dict,
        nlp: Optional[NLPResult] = None,
    ) -> AnalysisResult:

        findings = self.remove_duplicates(
            findings
        )

        risk_score = self.calculate_final_score(
            findings,
            nlp,
        )

        risk_level = self.calculate_risk_level(
            risk_score
        )

        confidence = self.calculate_final_confidence(
            findings,
            context,
            nlp,
        )

        summary = self.generate_summary(
            findings,
            risk_level,
            context,
            nlp,
        )

        return AnalysisResult(
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            summary=summary,
            findings=findings,
            document_type=context.document_type,
            document_confidence=context.confidence,
            entities=entities,
            nlp=nlp,
        )


# ==========================================================
# Singleton
# ==========================================================

scoring_engine = ScoringEngine()