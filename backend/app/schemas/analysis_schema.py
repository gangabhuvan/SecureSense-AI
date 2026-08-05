"""
analysis_schema.py

API schemas for the unified SecureSense AI analysis pipeline.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict

from app.fcp.models import FinancialCommunicationPassport


# ==========================================================
# Finding Schema
# ==========================================================

class FindingSchema(BaseModel):
    """
    Explainable fraud indicator produced by the rule engine.
    """

    category: str
    severity: str
    score: int
    matched_text: str
    explanation: str

    evidence: Dict[str, Any] = {}

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# DistilBERT NLP Result
# ==========================================================

class NLPResultSchema(BaseModel):
    """
    Classification produced by the trained DistilBERT model.
    """

    label: str
    class_id: int

    # Probability from 0.0 to 1.0
    confidence: float

    # UI-friendly percentage from 0 to 100
    confidence_percent: float

    probabilities: Dict[str, float]

    inference_time_ms: float

    # ML-derived security risk from 0 to 100
    risk_score: float

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Unified Analysis Response
# ==========================================================

class AnalysisResponse(BaseModel):
    """
    Complete response from POST /analysis/analyse.
    """

    risk_score: int
    risk_level: str
    confidence: float
    summary: str

    document_type: str
    document_confidence: float

    findings: List[FindingSchema]

    entities: Dict[str, Any]

    nlp: Optional[NLPResultSchema] = None

    passport: Optional[
        FinancialCommunicationPassport
    ] = None

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Communication History
# ==========================================================

class CommunicationResponse(BaseModel):

    id: int

    filename: str
    file_type: str

    risk_score: int
    risk_level: str
    confidence: float

    document_type: str
    document_confidence: float

    summary: str

    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Communication Detail
# ==========================================================

class CommunicationDetailResponse(BaseModel):

    id: int

    filename: str
    file_type: str

    ocr_text: str

    risk_score: int
    risk_level: str
    confidence: float

    document_type: str
    document_confidence: float

    summary: str

    entities: Dict[str, Any]

    findings: List[
        Dict[str, Any]
    ]

    processing_time: Optional[float]

    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


# ==========================================================
# Generic Message
# ==========================================================

class MessageResponse(BaseModel):

    message: str