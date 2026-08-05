from datetime import datetime
from typing import Any

from pydantic import BaseModel


class DocumentResponse(BaseModel):
    communication_id: str

    filename: str | None = None
    file_type: str | None = None
    status: str | None = None
    uploaded_at: datetime | None = None

    ocr_status: str | None = None
    extracted_text: str | None = None

    risk_score: float
    risk_level: str | None = None
    confidence: float | None = None

    document_type: str | None = None
    document_confidence: float | None = None

    summary: str | None = None

    entities: dict[str, Any] | None = None
    findings: list[Any] | None = None

    # ------------------------------------------------------
    # Persisted Rich Analysis Snapshot
    # ------------------------------------------------------

    nlp_result: dict[str, Any] | None = None

    visual_result: dict[str, Any] | None = None

    url_results: list[dict[str, Any]] | None = None
    domain_verification: list[dict[str, Any]] | None = None
    multimodal_fusion: dict[str, Any] | None = None
    communication_intent: dict[str, Any] | None = None
    evidence_references: dict[str, Any] | None = None

    passport: dict[str, Any] | None = None

    processing_time: float | None = None

    class Config:
        from_attributes = True