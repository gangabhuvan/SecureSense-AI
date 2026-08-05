"""
labels.py

Loads the label mapping used during DistilBERT training.

This file is the single source of truth for class names.
"""

from __future__ import annotations

import json
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent / "model"

LABEL_FILE = MODEL_DIR / "label_mapping.json"

if not LABEL_FILE.exists():
    raise FileNotFoundError(
        f"Missing label mapping file: {LABEL_FILE}"
    )

with open(LABEL_FILE, "r", encoding="utf-8") as f:
    mapping = json.load(f)

ID_TO_LABEL = {
    int(k): v
    for k, v in mapping["id2label"].items()
}

LABEL_TO_ID = mapping["label2id"]

NUM_CLASSES = len(ID_TO_LABEL)


def get_label(class_id: int) -> str:
    """
    Returns label name from class id.
    """

    return ID_TO_LABEL[class_id]


def get_class_id(label: str) -> int:
    """
    Returns class id from label.
    """

    return LABEL_TO_ID[label]