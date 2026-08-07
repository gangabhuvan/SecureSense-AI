"""
aasist_predictor.py

Spectra-AASIST3 predictor for SecureSense AI.

Responsibilities
----------------
- Load Spectra-AASIST3 once
- Load pretrained weights from Hugging Face
- Run voice authenticity inference
- Return VoiceModelPrediction
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from time import perf_counter

import librosa
import torch
import torch.nn.functional as F
from huggingface_hub import hf_hub_download

from app.ai.voice.detector import BaseVoiceDetector
from app.models.voice_models import VoiceModelPrediction


MODEL_ID = "lab260/Spectra-AASIST3"


class AASISTPredictor(BaseVoiceDetector):

    def __init__(self):

        super().__init__()

        self.device = (
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        self.model = None

    @property
    def model_name(self):

        return "Spectra-AASIST3"

    @property
    def model_version(self):

        return "1.0"

    @property
    def model_type(self):

        return "Voice Anti-Spoofing"

    # =====================================================
    # Load
    # =====================================================

    def load(self):

        if self.loaded:
            return


        model_file = hf_hub_download(
            repo_id=MODEL_ID,
            filename="model.py",
        )

        spec = importlib.util.spec_from_file_location(
            "spectra_model",
            model_file,
        )

        module = importlib.util.module_from_spec(
            spec,
        )

        spec.loader.exec_module(module)

        self.model = (
            module.spectra_aasist3.from_pretrained(
                MODEL_ID
            )
        )

        self.model.to(self.device)

        self.model.eval()

        self.loaded = True


    # =====================================================
    # Audio preprocessing
    # =====================================================

    def _prepare_audio(
        self,
        audio_path: str | Path,
    ):

        waveform, _ = librosa.load(
            audio_path,
            sr=16000,
            mono=True,
        )

        waveform = torch.from_numpy(
            waveform
        ).float()

        target = 64600

        if waveform.shape[0] < target:
            waveform = F.pad(
                waveform,
                (
                    0,
                    target - waveform.shape[0],
                ),
            )

        else:
            waveform = waveform[:target]

        return waveform.unsqueeze(0).to(
            self.device
        )

    # =====================================================
    # Predict
    # =====================================================

    @torch.inference_mode()
    def predict(
        self,
        audio_path,
    ) -> VoiceModelPrediction:

        start = perf_counter()

        audio = self._prepare_audio(
            audio_path
        )

        logits = self.model(
            audio
        )

        probabilities = F.softmax(
            logits,
            dim=1,
        )[0]

        genuine = float(
            probabilities[0]
        )

        synthetic = float(
            probabilities[1]
        )

        label = (
            "Synthetic"
            if synthetic >= genuine
            else "Genuine"
        )

        confidence = max(
            genuine,
            synthetic,
        )

        inference_time = (
            perf_counter() - start
        ) * 1000

        return VoiceModelPrediction(

            model_name=self.model_name,

            model_version=self.model_version,

            model_type=self.model_type,

            label=label,

            class_id=(
                1
                if label == "Synthetic"
                else 0
            ),

            confidence=confidence,

            confidence_percent=round(
                confidence * 100,
                2,
            ),

            genuine_probability=genuine,

            spoof_probability=synthetic,

            risk_score=round(
                synthetic * 100
            ),

            inference_time_ms=round(
                inference_time,
                2,
            ),
        )


aasist_predictor = (
    AASISTPredictor()
)