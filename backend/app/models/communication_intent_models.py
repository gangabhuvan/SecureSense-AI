"""
communication_intent_models.py

Models for Communication Intent Intelligence (CII).

CII determines the semantic intent of a communication
independently from NLP phishing classification.
"""

from __future__ import annotations

from typing import List
from pydantic import BaseModel


# ==========================================================
# Evidence
# ==========================================================

class IntentEvidence(BaseModel):

    feature: str

    score: float

    description: str


# ==========================================================
# Result
# ==========================================================

class CommunicationIntentResult(BaseModel):

    context: str

    context_confidence: float

    security_intent: str

    confidence: float

    risk_score: float

    evidence: List[IntentEvidence]