"""
voice_analysis_service.py

Voice Intelligence orchestration service.

Pipeline
--------
Audio
    ↓
Whisper Speech-to-Text
    ↓
Existing NLP Intelligence
    ↓
Structured Voice Analysis

This service intentionally reuses the existing
analysis_service so that voice communications follow
the same intelligence pipeline as text communications.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.analysis_service import (
    analysis_service,
)

from app.services.voice_transcription_service import (
    voice_transcription_service,
)


class VoiceAnalysisService:
    """
    High-level Voice Intelligence pipeline.
    """

    def analyse(
        self,
        audio_path: str | Path,
    ) -> dict[str, Any]:

        # ====================================================
        # 1. Whisper Transcription
        # ====================================================

        transcription = (
            voice_transcription_service.transcribe(
                audio_path
            )
        )

        transcript = transcription[
            "transcript"
        ]

        # ====================================================
        # 2. Existing NLP Intelligence
        # ====================================================

        analysis = (
            analysis_service.analyse(
                transcript
            )
        )

        # ====================================================
        # 3. Override Communication Modality
        # ====================================================
        #
        # The transcript is analysed by the existing NLP
        # pipeline, but the uploaded communication itself is
        # still a Voice communication.
        #
        # This keeps downstream modules (Upload History,
        # Reports, FCP, Dashboard, etc.) modality-aware.
        #
        # We intentionally DO NOT overwrite
        # document_confidence because Voice is determined from
        # the uploaded media type rather than predicted by an
        # AI classifier.
        # ====================================================

        analysis.document_type = "Voice"

        # ====================================================
        # 4. Structured Response
        # ====================================================

        return {

            "module":
                "Voice Intelligence",

            "communication_type":
                "Voice",

            "voice":
                transcription,

            "analysis":
                analysis,
        }


voice_analysis_service = (
    VoiceAnalysisService()
)