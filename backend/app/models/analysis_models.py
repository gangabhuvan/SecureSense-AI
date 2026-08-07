"""
analysis_models.py

Core domain models used by the SecureSense AI analysis pipeline.

The final AnalysisResult combines:
- Rule-based fraud indicators
- Document/context analysis
- Entity extraction
- DistilBERT NLP classification
- Financial Communication Passport
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.fcp.models import FinancialCommunicationPassport


# ==========================================================
# Fraud Finding
# ==========================================================

@dataclass
class Finding:
    """
    Represents a single explainable fraud indicator detected
    in the analysed communication/document.
    """

    category: str
    severity: str
    score: int
    matched_text: str
    explanation: str

    evidence: Dict[str, Any] = field(
        default_factory=dict
    )


# ==========================================================
# Document Context
# ==========================================================

@dataclass
class DocumentContext:
    """
    Represents the detected document/communication context.
    """

    document_type: str

    confidence: float

    matched_keywords: List[str] = field(
        default_factory=list
    )


# ==========================================================
# NLP Classification Result
# ==========================================================

@dataclass
class NLPResult:
    """
    DistilBERT classification result.

    The classifier predicts one of:

    - Legitimate
    - Spam
    - Phishing
    """

    label: str

    class_id: int

    # Raw probability in the range 0.0 - 1.0
    confidence: float

    # UI-friendly percentage in the range 0 - 100
    confidence_percent: float

    # Per-class probabilities represented as percentages
    probabilities: Dict[str, float] = field(
        default_factory=dict
    )

    inference_time_ms: float = 0.0

    # Risk signal derived from the ML classification.
    # This will be calculated by the fusion/scoring layer.
    risk_score: float = 0.0
    communication_text: str = ""


# ==========================================================
# Analysis Result
# ==========================================================

@dataclass
class AnalysisResult:
    """
    Complete SecureSense AI analysis result.

    Combines:
    - Deterministic fraud evidence
    - ML-based NLP classification
    - Explainable Evidence Ledger references
    - Financial Communication Passport
    """

    # ------------------------------------------------------
    # Final fused risk assessment
    # ------------------------------------------------------

    risk_score: float

    risk_level: str

    confidence: float

    summary: str

    # ------------------------------------------------------
    # Explainable rule-based findings
    # ------------------------------------------------------

    findings: List[Finding] = field(
        default_factory=list
    )

    # ------------------------------------------------------
    # Document/context classification
    # ------------------------------------------------------

    document_type: str = "Unknown"

    document_confidence: float = 0.0

    # ------------------------------------------------------
    # Extracted entities
    # ------------------------------------------------------

    entities: Dict[str, Any] = field(
        default_factory=dict
    )

    # ------------------------------------------------------
    # DistilBERT NLP classification
    # ------------------------------------------------------

    nlp: Optional[NLPResult] = None

    # ------------------------------------------------------
    # Explainable Evidence Ledger
    #
    # These are references to evidence already committed
    # to the central EEL. The complete explanation remains
    # in the ledger rather than being duplicated here.
    # ------------------------------------------------------

    evidence_ids: List[str] = field(
        default_factory=list
    )

    ledger_ids: List[str] = field(
        default_factory=list
    )

    evidence_modules: List[str] = field(
        default_factory=list
    )
    trusted_hosting_platform: bool = False
    hosting_provider: Optional[str] = None
    # ------------------------------------------------------
    # Financial Communication Passport
    # ------------------------------------------------------

    passport: Optional[
        FinancialCommunicationPassport
    ] = None