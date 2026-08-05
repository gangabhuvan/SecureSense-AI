"""
voice_transcription_service.py

Voice Intelligence transcription service.

Responsibilities
----------------
- Validate audio input
- Measure audio duration
- Invoke Whisper
- Return a structured transcription result
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import soundfile as sf

from app.services.voice_model_service import (
    voice_model_service,
)


class VoiceTranscriptionService:
    """
    High-level transcription service.

    Wraps Whisper inference and exposes
    a structured SecureSense AI response.
    """

    SUPPORTED_EXTENSIONS = {
        ".wav",
        ".mp3",
        ".m4a",
        ".flac",
        ".ogg",
    }

    # ====================================================
    # Validate
    # ====================================================

    def _validate(
        self,
        audio_path: str | Path,
    ) -> Path:

        audio_path = Path(audio_path)

        if not audio_path.exists():
            raise FileNotFoundError(
                f"Audio not found: {audio_path}"
            )

        if (
            audio_path.suffix.lower()
            not in self.SUPPORTED_EXTENSIONS
        ):
            raise ValueError(
                f"Unsupported audio type: {audio_path.suffix}"
            )

        return audio_path

    # ====================================================
    # Duration
    # ====================================================

    @staticmethod
    def _duration_seconds(
        audio_path: Path,
    ) -> float:

        info = sf.info(audio_path)

        return round(
            info.frames / info.samplerate,
            2,
        )

    # ====================================================
    # Transcribe
    # ====================================================

    def transcribe(
        self,
        audio_path: str | Path,
    ) -> dict[str, Any]:

        audio_path = self._validate(
            audio_path
        )

        duration = self._duration_seconds(
            audio_path
        )

        whisper_result = (
            voice_model_service.transcribe(
                audio_path
            )
        )

        return {

            "module":
                "Voice Intelligence",

            "transcript":
                whisper_result["transcript"],

            "language":
                whisper_result["language"],

            "duration_seconds":
                duration,

            "segment_count":
                len(
                    whisper_result[
                        "segments"
                    ]
                ),

            "segments":
                whisper_result[
                    "segments"
                ],

            "model":
                "Whisper Base",

            "inference_time_ms":
                whisper_result[
                    "inference_time_ms"
                ],
        }


voice_transcription_service = (
    VoiceTranscriptionService()
)