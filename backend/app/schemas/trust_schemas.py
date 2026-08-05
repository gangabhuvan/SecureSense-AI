"""
trust_schema.py

API response schemas for the SecureSense AI Trust Layer.

These schemas wrap the existing fraud analysis with the
Financial Communication Passport (FCP).

Future versions will also include:
    - Explainable Evidence Ledger (EEL)
    - Securities Trust Graph (STG)
"""

from typing import List, Dict, Any

from pydantic import BaseModel

from app.fcp.models import FinancialCommunicationPassport


class FindingSchema(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    matched_text: str
    score: int
    recommendation: str
    evidence: Dict[str, Any]


class AnalysisSchema(BaseModel):
    risk_score: int
    risk_level: str
    confidence: float
    summary: str
    document_type: str
    document_confidence: float
    findings: List[FindingSchema]
    entities: Dict[str, Any]


class TrustResponse(BaseModel):
    """
    Complete SecureSense AI response.

    Version 1
    ----------
    - Fraud Analysis
    - Financial Communication Passport

    Future
    ------
    - Evidence Ledger
    - Trust Graph
    """

    analysis: AnalysisSchema

    passport: FinancialCommunicationPassport