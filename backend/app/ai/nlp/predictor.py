"""
predictor.py

Production-grade inference pipeline for the trained
DistilBERT email security classifier.

Classes:
- Legitimate
- Spam
- Phishing
"""

from __future__ import annotations

import time
from typing import Any, Dict

import torch
import torch.nn.functional as F

from .inference import (
    get_device,
    get_model,
    get_tokenizer,
)
from .labels import ID_TO_LABEL


# ==========================================================
# Configuration
# ==========================================================

# Must match the maximum sequence length used during training.
MAX_LENGTH = 256

# Enable only during local debugging.
# Raw logits should not normally be exposed through the API.
DEBUG = False


# ==========================================================
# Text Preprocessing
# ==========================================================

def _clean_text(text: str) -> str:
    """
    Apply lightweight normalization before tokenization.

    This intentionally avoids aggressive preprocessing because
    DistilBERT was trained on natural text and may rely on
    punctuation, URLs, and other textual signals.
    """

    return " ".join(text.strip().split())


# ==========================================================
# Prediction
# ==========================================================

def predict_email(text: str) -> Dict[str, Any]:
    """
    Classify email/text content as Legitimate, Spam, or Phishing.

    Parameters
    ----------
    text : str
        Raw text to classify.

    Returns
    -------
    Dict[str, Any]
        JSON-serializable prediction containing:
        - label
        - class_id
        - confidence (0-1)
        - confidence_percent (0-100)
        - class probabilities (0-100)
        - inference latency
    """

    # ------------------------------------------------------
    # Input validation
    # ------------------------------------------------------

    if not isinstance(text, str):
        raise TypeError("Input text must be a string.")

    text = _clean_text(text)

    if not text:
        raise ValueError("Input text cannot be empty.")

    # ------------------------------------------------------
    # Shared model resources
    # ------------------------------------------------------

    tokenizer = get_tokenizer()
    model = get_model()
    device = get_device()

    # ------------------------------------------------------
    # Tokenization
    # ------------------------------------------------------

    encoded = tokenizer(
        text,
        max_length=MAX_LENGTH,
        truncation=True,
        padding="max_length",
        return_tensors="pt",
    )

    encoded = {
        key: value.to(device)
        for key, value in encoded.items()
    }

    # ------------------------------------------------------
    # Model inference
    # ------------------------------------------------------

    start_time = time.perf_counter()

    with torch.inference_mode():
        encoded.pop("token_type_ids", None)
        outputs = model(**encoded)
        logits = outputs.logits
        probabilities = F.softmax(logits, dim=-1)

    inference_time_ms = (
        time.perf_counter() - start_time
    ) * 1000.0

    # ------------------------------------------------------
    # Prediction extraction
    # ------------------------------------------------------

    probabilities = probabilities.squeeze(0)

    confidence_tensor, prediction_tensor = torch.max(
        probabilities,
        dim=0,
    )

    class_id = int(prediction_tensor.item())
    confidence = float(confidence_tensor.item())

    if class_id not in ID_TO_LABEL:
        raise RuntimeError(
            f"Model returned unknown class ID: {class_id}"
        )

    # ------------------------------------------------------
    # Class probabilities
    # ------------------------------------------------------

    probability_dict = {
        ID_TO_LABEL[class_id]: round(
            float(probabilities[class_id].item()) * 100.0,
            4,
        )
        for class_id in sorted(ID_TO_LABEL)
    }

    # ------------------------------------------------------
    # Response
    # ------------------------------------------------------

    response: Dict[str, Any] = {
        "label": ID_TO_LABEL[class_id],

        # Machine-friendly probability: 0.0 - 1.0
        "confidence": round(confidence, 6),

        # UI-friendly percentage: 0 - 100
        "confidence_percent": round(
            confidence * 100.0,
            4,
        ),

        "class_id": class_id,

        # Percentages for frontend visualization
        "probabilities": probability_dict,

        "inference_time_ms": round(
            inference_time_ms,
            2,
        ),
    }

    # ------------------------------------------------------
    # Optional development diagnostics
    # ------------------------------------------------------

    if DEBUG:
        response["logits"] = [
            round(float(value), 6)
            for value in logits.squeeze(0).detach().cpu().tolist()
        ]

    return response