"""
predictor.py

Official AASIST Predictor Interface.

This module defines the adapter interface between the
official AASIST implementation and SecureSense AI.

The official repository remains untouched.
This adapter converts AASIST outputs into SecureSense AI
domain models.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.models.voice_models import (
    VoiceModelPrediction,
)


class BaseAASISTPredictor(ABC):
    """
    Abstract interface for AASIST predictors.

    Concrete implementations must wrap the official
    AASIST implementation without modifying it.
    """

    @abstractmethod
    def load(self) -> None:
        """
        Load the pretrained AASIST model.
        """
        raise NotImplementedError

    @abstractmethod
    def predict(
        self,
        audio_path: str | Path,
    ) -> VoiceModelPrediction:
        """
        Predict whether an audio sample is
        Genuine or Synthetic.

        Parameters
        ----------
        audio_path:
            Path to the audio file.

        Returns
        -------
        VoiceModelPrediction
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def model_name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def model_version(self) -> str:
        raise NotImplementedError