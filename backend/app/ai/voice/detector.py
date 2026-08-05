"""
detector.py

Base interface for all Voice AI detectors.

Every voice detector used by SecureSense AI must inherit
from BaseVoiceDetector.

Examples
--------
- Whisper
- Wav2Vec2
- W2V2+AASIST
- RawNet2 (future)
- ECAPA (future)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.models.voice_models import (
    VoiceModelPrediction,
)


class BaseVoiceDetector(ABC):
    """
    Abstract base class for every Voice AI detector.
    """

    def __init__(self):

        self.loaded = False

    @abstractmethod
    def load(self) -> None:
        """
        Load model into memory.
        """
        ...

    @abstractmethod
    def predict(
        self,
        audio_path: str | Path,
    ) -> VoiceModelPrediction:
        """
        Run inference on an audio file.
        """
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...

    @property
    @abstractmethod
    def model_version(self) -> str:
        ...

    @property
    @abstractmethod
    def model_type(self) -> str:
        ...