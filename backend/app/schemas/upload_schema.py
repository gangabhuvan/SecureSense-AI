"""
upload_schema.py

Response schemas for the SecureSense AI unified multimodal
communication-analysis pipeline.

Supported communication inputs:
- Uploaded documents/images
- Direct pasted text

The response exposes:
- Communication metadata
- OCR/text-extraction information
- DistilBERT NLP intelligence
- ConvNeXt visual intelligence
- XGBoost URL intelligence
- Multimodal model-preserving fusion
- Securities Trust Graph intelligence
- Explainable Evidence Ledger references
- Financial Communication Passport
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.fcp.models import (
    FinancialCommunicationPassport,
)


# ============================================================
# Upload / Communication Section
# ============================================================

class UploadInfo(BaseModel):
    """
    Metadata for the analysed communication.
    """

    communication_id: str

    filename: Optional[str] = None

    file_type: Optional[str] = None

    status: str

    uploaded_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# OCR / Text Extraction Section
# ============================================================

class OCRInfo(BaseModel):
    """
    Text-extraction information.

    For pasted text, status may be "Not Required".
    """

    status: str

    text_length: int


# ============================================================
# NLP Intelligence
# ============================================================

class NLPInfo(BaseModel):
    """
    DistilBERT NLP security-classification result.
    """

    label: str

    class_id: int

    confidence: float

    confidence_percent: float

    probabilities: dict[
        str,
        float,
    ] = Field(
        default_factory=dict
    )

    inference_time_ms: float

    risk_score: float

    communication_text: str


# ============================================================
# Visual Intelligence
# ============================================================

class VisualInfo(BaseModel):
    """
    ConvNeXt-Tiny visual phishing result.

    Present only when visual intelligence was applicable and
    completed successfully.
    """

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

    inference_time_ms: float

    image_width: int

    image_height: int


# ============================================================
# URL Explainability
# ============================================================

class URLExplanationInfo(BaseModel):
    """
    Native TreeSHAP explanation for one URL feature.
    """

    feature: str

    value: float

    shap_value: float

    direction: str

    strength: float


# ============================================================
# URL Intelligence
# ============================================================

class URLInfo(BaseModel):
    """
    XGBoost URL phishing-analysis result.

    One communication may contain multiple URLs, therefore the
    analysis response contains a list of URLInfo objects.
    """

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

    inference_time_ms: float

    model_info: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )

    explanation: list[
        URLExplanationInfo
    ] = Field(
        default_factory=list
    )

    evidence_id: str

    ledger_id: str


# ============================================================
# Multimodal Fusion
# ============================================================

class MultimodalFusionInfo(BaseModel):
    """
    Final model-preserving multimodal fusion result.

    Communication-security signals may include:
    - NLP
    - Vision
    - URL Intelligence

    Voice Authenticity is reported separately as a speaker-level
    security attribute and does not participate in communication-
    security agreement analysis.

    The strongest learned phishing probability is preserved
    rather than replaced by arbitrary weighted averaging.
    """

    risk_score: float

    risk_level: str

    confidence: float

    decision: str

    agreement: str

    dominant_modality: str

    nlp_risk: Optional[float] = None

    visual_risk: Optional[float] = None

    url_risk: Optional[float] = None

    voice_risk: Optional[float] = None

    nlp_label: Optional[str] = None

    visual_label: Optional[str] = None

    url_label: Optional[str] = None

    voice_label: Optional[str] = None

    voice_summary: Optional[str] = None

    summary: str


# ============================================================
# Securities Trust Graph
# ============================================================

class SecuritiesTrustGraphInfo(BaseModel):
    """
    Securities Trust Graph analysis exposed at the
    communication level.

    The STG represents historical entity-specific trust and
    risk intelligence.

    It does NOT authenticate the sender.

    Sender authenticity remains exclusively controlled by the
    Authenticity Verification Engine (AVE).

    The graph context is intentionally represented as a
    flexible dictionary because it contains nested graph nodes,
    edges, entity reputations and graph evidence that may
    evolve independently from the public communication schema.
    """

    available: bool = False

    communication_id: Optional[str] = None

    analysed_at: Optional[datetime] = None

    nodes_added: int = 0

    edges_added: int = 0

    nodes_updated: int = 0

    edges_updated: int = 0

    entities_analysed: int = 0

    reputation_available: bool = False

    reputation_score: Optional[float] = None

    graph_risk_score: Optional[float] = None

    graph_trust_score: Optional[float] = None

    confidence: float = 0.0

    classification: str = "Unknown"

    context: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )

    evidence_ids: list[str] = Field(
        default_factory=list
    )

    ledger_ids: list[str] = Field(
        default_factory=list
    )

    summary: str = ""


# ============================================================
# Explainable Evidence Ledger
# ============================================================

class EvidenceInfo(BaseModel):
    """
    References to evidence committed to the central
    Explainable Evidence Ledger.
    """

    evidence_ids: list[str] = Field(
        default_factory=list
    )

    ledger_ids: list[str] = Field(
        default_factory=list
    )

    modules: list[str] = Field(
        default_factory=list
    )


# ============================================================
# Analysis Section
# ============================================================

class AnalysisInfo(BaseModel):
    """
    Complete communication-level SecureSense AI analysis.
    """

    # --------------------------------------------------------
    # Final fused risk
    # --------------------------------------------------------

    risk_score: float

    risk_level: str

    confidence: float

    # --------------------------------------------------------
    # Communication context
    # --------------------------------------------------------

    document_type: str

    document_confidence: float

    # --------------------------------------------------------
    # Human-readable analysis
    # --------------------------------------------------------

    summary: str

    findings: list[Any] = Field(
        default_factory=list
    )

    entities: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict
    )

    # --------------------------------------------------------
    # DistilBERT NLP
    # --------------------------------------------------------

    nlp: Optional[
        NLPInfo
    ] = None

    # --------------------------------------------------------
    # ConvNeXt Visual Intelligence
    # --------------------------------------------------------

    visual: Optional[
        VisualInfo
    ] = None

    voice: Optional[
        dict[str, Any]
    ] = None

    qr: Optional[
        dict[str, Any]
    ] = None

    # --------------------------------------------------------
    # XGBoost URL Intelligence
    # --------------------------------------------------------

    urls: list[
        URLInfo
    ] = Field(
        default_factory=list
    )

    # --------------------------------------------------------
    # Multimodal Fusion
    # --------------------------------------------------------

    multimodal_fusion: Optional[
        MultimodalFusionInfo
    ] = None

    # --------------------------------------------------------
    # Securities Trust Graph
    # --------------------------------------------------------

    securities_trust_graph: Optional[
        SecuritiesTrustGraphInfo
    ] = None

    # --------------------------------------------------------
    # Explainable Evidence Ledger
    # --------------------------------------------------------

    evidence: EvidenceInfo = Field(
        default_factory=EvidenceInfo
    )

    # --------------------------------------------------------
    # Final Financial Communication Passport
    # --------------------------------------------------------

    passport: Optional[
        FinancialCommunicationPassport
    ] = None


# ============================================================
# Final Unified Response
# ============================================================

class UploadResponse(BaseModel):
    """
    Complete response after a communication passes through the
    SecureSense AI multimodal trust-intelligence pipeline.
    """

    upload: UploadInfo

    ocr: OCRInfo

    analysis: AnalysisInfo

    processing_time: float


# ============================================================
# Communication History
# ============================================================

class UploadHistoryResponse(BaseModel):
    """
    Compact persisted communication-history record.
    """

    communication_id: str

    filename: Optional[str] = None

    file_type: Optional[str] = None

    status: str

    uploaded_at: datetime

    class Config:
        from_attributes = True