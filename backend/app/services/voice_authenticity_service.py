"""
voice_authenticity_service.py

Voice Authenticity Intelligence Service.

Responsibilities
----------------
- Execute Spectra-AASIST3
- Produce structured voice authenticity result
- Calculate authenticity risk
- Generate business-friendly recommendations

This service intentionally wraps the underlying
voice AI model so the rest of SecureSense AI
(Fusion, FCP, STG, EEL) remains model-agnostic.
"""

from __future__ import annotations

from pathlib import Path

from app.ai.voice.aasist_predictor import (
    aasist_predictor,
)

from app.models.voice_models import (
    VoiceAuthenticityResult,
    VoiceConsensus,
)


class VoiceAuthenticityService:

    def __init__(self):

        self.detector = aasist_predictor

    # ======================================================
    # Public API
    # ======================================================

    def analyse(
        self,
        audio_path: str | Path,
    ) -> VoiceAuthenticityResult:

        if not self.detector.loaded:
            self.detector.load()

        prediction = self.detector.predict(
            audio_path
        )

        recommendation = self._recommendation(
            prediction.label
        )

        consensus = VoiceConsensus(

            final_label=prediction.label,

            confidence=prediction.confidence,

            confidence_percent=prediction.confidence_percent,

            agreement=True,

            agreement_level="Single Model",

            dominant_model=prediction.model_name,

            recommendation=recommendation,

            reasoning=[
                (
                    "Voice authenticity determined using "
                    "Spectra-AASIST3."
                ),
            ],
        )

        return VoiceAuthenticityResult(

            available=True,

            prediction=prediction.label,

            risk_score=prediction.risk_score,

            confidence=prediction.confidence,

            confidence_percent=prediction.confidence_percent,

            recommendation=recommendation,

            voice_model=prediction,

            consensus=consensus,

            evidence={
                "model": prediction.model_name,
                "model_version": prediction.model_version,
                "spoof_probability": prediction.spoof_probability,
                "genuine_probability": prediction.genuine_probability,
            },

            metadata={
                "model_type": prediction.model_type,
                "inference_time_ms": prediction.inference_time_ms,
            },
        )

    # ======================================================
    # Recommendation
    # ======================================================

    def _recommendation(
        self,
        label: str,
    ) -> str:

        if label.lower() == "synthetic":

            return (
                "High probability of AI-generated or spoofed "
                "speech detected. Verify the caller using an "
                "official communication channel before acting."
            )

        return (
            "No strong evidence of AI-generated or spoofed "
            "speech was detected."
        )


voice_authenticity_service = (
    VoiceAuthenticityService()
)