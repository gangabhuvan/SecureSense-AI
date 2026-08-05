"""
inference.py

Production-grade singleton loader for the DistilBERT phishing classifier.

Responsibilities
----------------
- Validate model assets
- Load tokenizer
- Load trained model
- Move model to the best available device
- Expose singleton instances
- Prevent accidental training
"""

from __future__ import annotations

import logging
from pathlib import Path
from threading import Lock

import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
)

logger = logging.getLogger(__name__)

# ============================================================
# Paths
# ============================================================

MODEL_DIR = Path(__file__).resolve().parent / "model"

REQUIRED_FILES = (
    "config.json",
    "model.safetensors",
    "tokenizer.json",
    "tokenizer_config.json",
    "label_mapping.json",
)

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        f"Model directory does not exist: {MODEL_DIR}"
    )

for file_name in REQUIRED_FILES:
    file_path = MODEL_DIR / file_name

    if not file_path.exists():
        raise FileNotFoundError(
            f"Required model file missing: {file_path}"
        )

# ============================================================
# Device
# ============================================================

DEVICE = torch.device(
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

logger.info(
    "NLP Device: %s | CUDA Available: %s",
    DEVICE,
    torch.cuda.is_available(),
)

# ============================================================
# Singleton objects
# ============================================================

_model = None
_tokenizer = None
_is_loaded = False

_lock = Lock()

# ============================================================
# Internal Loader
# ============================================================


def _load() -> None:
    """
    Loads tokenizer and model exactly once.
    """

    global _model
    global _tokenizer
    global _is_loaded

    logger.info(
        "Loading DistilBERT model from %s",
        MODEL_DIR,
    )

    _tokenizer = AutoTokenizer.from_pretrained(
        MODEL_DIR,
        use_fast=True,
    )

    _model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_DIR,
    )

    _model.to(DEVICE)

    _model.eval()

    # Disable gradients permanently
    for parameter in _model.parameters():
        parameter.requires_grad = False

    _is_loaded = True

    logger.info(
        "DistilBERT model loaded successfully."
    )


# ============================================================
# Public API
# ============================================================


def get_model():
    """
    Returns the singleton model instance.
    """

    global _model

    if _model is None:
        with _lock:
            if _model is None:
                _load()

    return _model


def get_tokenizer():
    """
    Returns the singleton tokenizer.
    """

    global _tokenizer

    if _tokenizer is None:
        with _lock:
            if _tokenizer is None:
                _load()

    return _tokenizer


def get_device() -> torch.device:
    """
    Returns the active inference device.
    """

    return DEVICE


def is_loaded() -> bool:
    """
    Returns True once the model has been loaded.
    """

    return _is_loaded


def model_directory() -> Path:
    """
    Returns the model directory.
    """

    return MODEL_DIR