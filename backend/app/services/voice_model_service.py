"""
voice_model_service.py

Whisper speech-to-text model service.

Responsibilities
----------------
- Load Whisper model once
- Transcribe audio
- Return raw Whisper output
"""

from __future__ import annotations

import os
from pathlib import Path
from time import perf_counter
from typing import Any

import torch
import whisper


class VoiceModelService:

    def __init__(self):

        self.device = (
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        # Hackathon recommendation:
        # base model is a good balance between
        # speed and accuracy.
        self.model = whisper.load_model(
            "base",
            device=self.device,
        )

    # ====================================================
    # Transcribe
    # ====================================================

    def transcribe(
        self,
        audio_path: str | Path,
    ) -> dict[str, Any]:

        audio_path = str(audio_path)

        start = perf_counter()

        result = self.model.transcribe(
            audio_path,
            fp16=(
                self.device == "cuda"
            ),
        )

        inference_time = (
            perf_counter() - start
        ) * 1000

        return {

            "transcript":
                result.get(
                    "text",
                    "",
                ).strip(),

            "language":
                result.get(
                    "language",
                    "unknown",
                ),

            "segments":
                result.get(
                    "segments",
                    [],
                ),

            "inference_time_ms":
                round(
                    inference_time,
                    2,
                ),
        }


voice_model_service = VoiceModelService()