"""
voice_models.py

Domain models for SecureSense AI Voice Intelligence.

These models are shared across:

- Spectra-AASIST3
- Voice Authenticity Service
- Multimodal Fusion
- Financial Communication Passport
- Explainable Evidence Ledger
- Securities Trust Graph
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ==========================================================
# Generic Voice Model Prediction
# ==========================================================

@dataclass
class VoiceModelPrediction:
    """
    Generic prediction returned by the Voice AI model.
    """

    # ------------------------------------------------------
    # Model Information
    # ------------------------------------------------------

    model_name: str

    model_version: str

    model_type: str

    # ------------------------------------------------------
    # Prediction
    # ------------------------------------------------------

    label: str

    class_id: int

    confidence: float

    confidence_percent: float

    # ------------------------------------------------------
    # Probabilities
    # ------------------------------------------------------

    genuine_probability: float = 0.0

    spoof_probability: float = 0.0

    probabilities: dict[str, float] = field(
        default_factory=dict
    )

    # ------------------------------------------------------
    # Security
    # ------------------------------------------------------

    risk_score: float = 0.0

    # ------------------------------------------------------
    # Explainability
    # ------------------------------------------------------

    reasoning: list[str] = field(
        default_factory=list
    )

    # ------------------------------------------------------
    # Performance
    # ------------------------------------------------------

    inference_time_ms: float = 0.0

    # ------------------------------------------------------
    # Extra Metadata
    # ------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


# ==========================================================
# Voice Decision Summary
# ==========================================================

@dataclass
class VoiceConsensus:
    """
    Final voice authenticity decision.

    Kept as a separate model so future ensemble models
    can be added without changing downstream modules.
    """

    final_label: str

    confidence: float

    confidence_percent: float

    agreement: bool = True

    agreement_level: str = "Single Model"

    dominant_model: str = ""

    recommendation: str = ""

    reasoning: list[str] = field(
        default_factory=list
    )


# ==========================================================
# Final Voice Authenticity Result
# ==========================================================

@dataclass
class VoiceAuthenticityResult:
    """
    Complete Voice Authenticity module output.
    """

    available: bool

    prediction: str

    risk_score: float

    confidence: float

    confidence_percent: float

    recommendation: str

    # ------------------------------------------------------
    # Voice AI Model
    # ------------------------------------------------------

    voice_model: VoiceModelPrediction

    # ------------------------------------------------------
    # Final Decision
    # ------------------------------------------------------

    consensus: VoiceConsensus

    # ------------------------------------------------------
    # Evidence
    # ------------------------------------------------------

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    # ------------------------------------------------------
    # Metadata
    # ------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict
    )