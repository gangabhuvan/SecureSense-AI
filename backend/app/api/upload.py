"""
upload.py

SecureSense AI unified multimodal communication API.

Supported inputs
----------------
1. Uploaded file:
   - PDF
   - Image
   - DOCX
   - TXT

2. Direct pasted text:
   - Email
   - SMS
   - Message
   - Financial communication
   - Other textual communication

Optional trusted sender/channel metadata
----------------------------------------
- sender_email
- sender_phone
- sender_website
- claimed_sender

Security boundary
-----------------
Sender/channel metadata is kept separate from entities extracted
from communication content.

A URL, email address or phone number appearing inside message
content is evidence about the content. It is not automatically
proof of sender authenticity.

Pipeline
--------
    File OR Pasted Text
            ↓
    Text Extraction / Direct Text
            ↓
    Text Intelligence
        ├── Entity Extraction
        ├── Context Detection
        ├── Rule Engine
        ├── DistilBERT NLP
        ├── Integrated Gradients
        └── NLP Evidence → EEL
            ↓
    URL Intelligence
        ├── Extract URLs from content entities
        ├── XGBoost URL model
        ├── Native TreeSHAP
        └── URL Evidence → EEL
            ↓
    Visual Intelligence
        ├── Image uploads only
        ├── ConvNeXt-Tiny
        ├── Grad-CAM
        └── Visual Evidence → EEL
            ↓
    Multimodal Fusion
        ├── NLP
        ├── Vision
        ├── URL
        └── Voice Authenticity
            ↓
        └── Strongest learned phishing signal
            ↓
    Securities Trust Graph
        ├── Persist content entity relationships
        ├── Record entity-specific URL security evidence
        ├── Preserve historical entity reputation
        └── Keep entity reputation separate from sender identity
            ↓
    Explicit Sender Metadata
            ↓
    Authenticity Verification Engine
            ↓
    One Final Financial Communication Passport
            ↓
    Persistence
            ↓
    API Response
"""
from __future__ import annotations
from app.core.auth import get_current_user
from app.database.models import User
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Any, List

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.crud import (
    get_communication_by_id,
    get_upload_history,
    update_analysis,
)
from app.database.database import get_db
from app.database.models import Communication

from app.schemas.document_schema import DocumentResponse
from app.schemas.upload_schema import (
    UploadHistoryResponse,
    UploadResponse,
)

from app.services.analysis_service import analysis_service
from app.services.multimodal_fusion_service import (
    multimodal_fusion_service,
)
from app.services.ocr_service import ocr_service
from app.services.trust_service import trust_service
from app.services.upload_service import (
    generate_communication_id,
    save_uploaded_file,
)
from app.services.url_analysis_service import (
    url_analysis_service,
)
from app.services.domain_verification_service import (
    domain_verification_service,
)
from app.services.visual_analysis_service import (
    visual_analysis_service,
)
from app.services.voice_analysis_service import (
    voice_analysis_service,
)

from app.services.voice_authenticity_service import (
    voice_authenticity_service,
)

from app.stg.graph_engine import graph_engine
from app.stg.graph_models import EvidenceSource

from app.eel.ledger import evidence_ledger
from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
)

from app.services.eel_persistence_service import (
    eel_persistence_service,
)

from app.services.qr_analysis_service import (
    qr_analysis_service,
)
from app.services.communication_intent_analysis_service import (
    communication_intent_analysis_service,
)
# ============================================================
# Configuration
# ============================================================

IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".tif",
    ".tiff",
}

AUDIO_EXTENSIONS = {
    ".wav",
    ".mp3",
    ".m4a",
    ".flac",
    ".ogg",
}

# ============================================================
# Router
# ============================================================

router = APIRouter(
    prefix="/upload",
    tags=["Upload"],
)


# ============================================================
# Helpers
# ============================================================

def _create_text_communication(
    text: str,
    db: Session,
) -> Communication:
    """
    Persist a direct pasted-text communication.

    No physical file is created.
    """

    communication = Communication(
        communication_id=(
            generate_communication_id()
        ),
        filename="Pasted Text",
        file_type="text",
        filepath=None,
        filesize=len(
            text.encode("utf-8")
        ),
        mime_type="text/plain",
        sha256=None,
        status="Uploaded",
        extracted_text=text,
        ocr_status="Not Required",
        uploaded_at=datetime.utcnow(),
    )

    db.add(
        communication
    )

    db.commit()

    db.refresh(
        communication
    )

    return communication


def _append_evidence_reference(
    result,
    *,
    evidence_id: str | None = None,
    ledger_id: str | None = None,
    module: str | None = None,
) -> None:
    """
    Add EEL references to AnalysisResult without duplicates.
    """

    if (
        evidence_id
        and evidence_id not in result.evidence_ids
    ):
        result.evidence_ids.append(
            evidence_id
        )

    if (
        ledger_id
        and ledger_id not in result.ledger_ids
    ):
        result.ledger_ids.append(
            ledger_id
        )

    if (
        module
        and module not in result.evidence_modules
    ):
        result.evidence_modules.append(
            module
        )


def _build_stg_entity_security_observations(
    url_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Convert URL Intelligence results into entity-specific
    Securities Trust Graph security observations.

    Important security boundary
    ---------------------------
    These observations describe the historical security
    reputation of the URL entity itself.

    They do NOT authenticate the sender of the communication.

    Therefore:

        verified = False

    even when URL Intelligence classifies a URL as Legitimate.

    Sender authenticity remains the responsibility of AVE.

    The dictionary is keyed by the original URL because the
    graph engine normalizes and resolves the corresponding
    persistent URL node.
    """

    observations: dict[
        str,
        dict[str, Any],
    ] = {}

    for url_result in url_results:

        url = url_result.get(
            "url"
        )

        label = url_result.get(
            "label"
        )

        if not url or not label:
            continue

        evidence_id = url_result.get(
            "evidence_id"
        )

        ledger_id = url_result.get(
            "ledger_id"
        )

        evidence_ids = (
            [evidence_id]
            if evidence_id
            else []
        )

        ledger_ids = (
            [ledger_id]
            if ledger_id
            else []
        )

        confidence = url_result.get(
            "confidence_percent"
        )

        if confidence is None:

            raw_confidence = url_result.get(
                "confidence"
            )

            if raw_confidence is not None:

                try:

                    raw_confidence = float(
                        raw_confidence
                    )

                    confidence = (
                        raw_confidence * 100.0
                        if 0.0
                        <= raw_confidence
                        <= 1.0
                        else raw_confidence
                    )

                except (
                    TypeError,
                    ValueError,
                ):

                    confidence = 0.0

        try:

            confidence = float(
                confidence or 0.0
            )

        except (
            TypeError,
            ValueError,
        ):

            confidence = 0.0

        confidence = max(
            0.0,
            min(
                100.0,
                confidence,
            ),
        )

        observations[url] = {

            "security_observation":
                str(label),

            # URL-model classification is security evidence,
            # not sender authentication.
            "verified":
                False,

            "confidence":
                confidence,

            "evidence_source":
                EvidenceSource.URL_INTELLIGENCE,

            "evidence_ids":
                evidence_ids,

            "ledger_ids":
                ledger_ids,

            "attributes": {

                "entity_specific_security_evidence":
                    True,

                "model_derived":
                    True,

                "authentication_evidence":
                    False,

                "source_module":
                    url_result.get(
                        "module",
                        "URL Intelligence",
                    ),

                "class_id":
                    url_result.get(
                        "class_id"
                    ),

                "risk_score":
                    url_result.get(
                        "risk_score"
                    ),

                "phishing_probability":
                    url_result.get(
                        "phishing_probability"
                    ),

                "phishing_probability_percent":
                    url_result.get(
                        "phishing_probability_percent"
                    ),

                "legitimate_probability":
                    url_result.get(
                        "legitimate_probability"
                    ),

                "legitimate_probability_percent":
                    url_result.get(
                        "legitimate_probability_percent"
                    ),
            },
        }

    return observations


# ============================================================
# Upload / Text + Analyse
# ============================================================

@router.post(
    "/",
    response_model=UploadResponse,
    summary="Analyse a communication",
    description="""
Analyse either an uploaded communication or directly pasted text.

Provide exactly one of:

- `file`
- `text`

Optional sender/channel metadata may also be supplied:

- `sender_email`
- `sender_phone`
- `sender_website`
- `claimed_sender`

These metadata fields are used only by the Authenticity
Verification Engine and Financial Communication Passport.

They are not mixed with entities extracted from communication
content.

File inputs can use OCR/content extraction, NLP intelligence,
URL intelligence and, for images, visual phishing intelligence.

Pasted text uses NLP intelligence and URL intelligence directly.

All available trained-model signals are fused without arbitrary
weighted averaging. Evidence is committed to EEL, entity-specific
security intelligence is recorded in the Securities Trust Graph,
and one final Financial Communication Passport is generated.
""",
)
async def upload_file(
    file: UploadFile | None = File(
        default=None
    ),

    text: str | None = Form(
        default=None
    ),

    sender_email: str | None = Form(
        default=None
    ),

    sender_phone: str | None = Form(
        default=None
    ),

    sender_website: str | None = Form(
        default=None
    ),

    claimed_sender: str | None = Form(
        default=None
    ),

    db: Session = Depends(
        get_db
    ),

    current_user: User = Depends(
        get_current_user
    ),
):
    """
    Execute the unified SecureSense AI trust-intelligence
    pipeline.
    """

    # ========================================================
    # 1. Validate Input
    # ========================================================

    normalized_text = (
        text.strip()
        if isinstance(text, str)
        else ""
    )

    has_file = (
        file is not None
        and bool(file.filename)
    )

    has_text = bool(
        normalized_text
    )

    if not has_file and not has_text:

        raise HTTPException(
            status_code=400,
            detail=(
                "Provide either an uploaded file "
                "or pasted text."
            ),
        )

    if has_file and has_text:

        raise HTTPException(
            status_code=400,
            detail=(
                "Provide either a file or pasted text, "
                "not both."
            ),
        )

    communication = None

    start_time = perf_counter()

    try:

        # ====================================================
        # 2. Create Communication
        # ====================================================

        if has_file:

            communication = save_uploaded_file(
                file,
                db,
            )

            extension = Path(
                communication.filepath
            ).suffix.lower()

            is_image = (
                extension in IMAGE_EXTENSIONS
            )

            is_audio = (
                extension in AUDIO_EXTENSIONS
            )

            input_mode = "file"

        else:

            communication = (
                _create_text_communication(
                    normalized_text,
                    db,
                )
            )

            extension = ""

            is_image = False

            is_audio = False

            input_mode = "text"

        # ====================================================
        # 3. Obtain Communication Text
        # ====================================================
        
        voice_result = None
        voice_authenticity = None
        voice_ledger_entry = None
        intent_result = None
        if input_mode == "file":
        
            if is_audio:
        
                voice_result = (
                    voice_analysis_service.analyse(
                        communication.filepath
                    )
                )

                voice_authenticity = (
                    voice_authenticity_service.analyse(
                        communication.filepath
                    )
                )

                if voice_authenticity.available:
                    voice_ledger_entry = (
                    evidence_ledger.record(
                        EvidenceRecord(
                            module="Voice Authenticity",

                            evidence_type=(
                                "synthetic_voice_detection"
                            ),
                            input_reference=(
                                communication.filename
                            ),

                            prediction=(
                                voice_authenticity.prediction
                            ),

                            confidence=(
                                voice_authenticity.confidence
                            ),

                            risk_score=(
                                voice_authenticity.risk_score
                            ),

                            model_info=(
                                EvidenceModelInfo(
                                    module=(
                                        "Voice Authenticity"
                                    ),

                                    model_type=(
                                        "Spectra-AASIST3"
                                    ),

                                    model_version="1.0",
                                )
                            ),

                            supporting_data={
                                "recommendation":
                                    voice_authenticity.recommendation,

                                "consensus":
                                    (
                                        voice_authenticity
                                        .consensus
                                        .final_label
                                    ),

                                "confidence_percent":
                                    (
                                        voice_authenticity
                                        .confidence_percent
                                    ),
                            },
                        )
                    )
                )
        
                extracted_text = (
                    voice_result["voice"]["transcript"]
                )
        
                result = (
                    voice_result["analysis"]
                )
        
                communication.extracted_text = (
                    extracted_text
                )
        
                communication.ocr_status = (
                    "Not Required"
                )
        
                db.commit()
        
                db.refresh(
                    communication
                )
        
            else:
        
                try:
        
                    extracted_text = (
                        ocr_service.extract_text(
                            communication.filepath
                        )
                    )
        
                    communication.extracted_text = (
                        extracted_text
                    )
        
                    communication.ocr_status = (
                        "Completed"
                    )
        
                except Exception:
        
                    extracted_text = ""
        
                    communication.extracted_text = ""
        
                    communication.ocr_status = (
                        "Failed"
                    )
        
                db.commit()
        
                db.refresh(
                    communication
                )
        
        else:
        
            extracted_text = normalized_text
        
            communication.extracted_text = (
                extracted_text
            )
        
            communication.ocr_status = (
                "Not Required"
            )
        
            db.commit()

        # ====================================================
        # 4. Text Intelligence
        # ====================================================

        if voice_result is None:

            result = (
                analysis_service.analyse(
                    extracted_text
                )
            )

            intent_result = (
                communication_intent_analysis_service.analyse(
                    extracted_text
                )
            )
# ====================================================
# Normalize Communication Type
# ====================================================

        if input_mode == "file":
            if is_audio:
                result.document_type = "Voice"

            elif is_image:
                result.document_type = "Image"

            elif extension == ".pdf":
                result.document_type = "PDF"

            elif extension == ".docx":
                result.document_type = "DOCX"
            elif extension == ".txt":
                result.document_type = "Text File"

        else:
            result.document_type = "Text"

        result.document_confidence = 100

        if (
            is_audio
            and voice_ledger_entry is not None
        ):
            _append_evidence_reference(
                result,

                evidence_id=(
                    voice_ledger_entry
                    .evidence
                    .evidence_id
                ),

                ledger_id=(
                    voice_ledger_entry
                    .ledger_id
                ),

                module="Voice Authenticity",
            )

        qr_result = None

        decoded_qr_urls = []

        if is_image:
            try:
                qr_result = (
                    qr_analysis_service.analyse(
                        communication.filepath,

                        input_reference=(
                            communication.filename
                        ),

                        content_type=(
                            communication.mime_type
                        ),

                        file_size_bytes=(
                            communication.filesize
                        ),
                    )
                )

                for qr_item in qr_result.get(
                    "qr_codes",
                    [],
                ):
                    _append_evidence_reference(
                        result,

                        evidence_id=(
                            qr_item.get(
                                "evidence_id"
                            )
                        ),

                        ledger_id=(
                            qr_item.get(
                                "ledger_id"
                            )
                        ),

                        module="QR Intelligence",
                    )

                    decoded_url = (
                        qr_item.get(
                            "decoded_url"
                        )
                    )

                    if decoded_url:
                        decoded_qr_urls.append(
                            decoded_url
                        )


            except Exception:
                qr_result = None

        # ====================================================
        # 5. URL Intelligence
        # ====================================================
        #
        # IMPORTANT:
        #
        # These URLs originate from communication CONTENT.
        #
        # They are valid inputs to URL Intelligence and later
        # become entity-specific STG security observations.
        #
        # They are never automatically treated as
        # sender-authentication metadata by AVE.
        # ====================================================

        url_results = []
        domain_results = []

        ocr_urls = (
            result.entities.get(
                "urls",
                [],
            )
            if result.entities
            else []
        )


        extracted_urls = list(
            dict.fromkeys(
                list(ocr_urls)
                + list(decoded_qr_urls)
            )
        )

        if result.entities is None:
            result.entities = {}
        result.entities["urls"] = extracted_urls

        for extracted_url in extracted_urls:

            try:

                url_result = (
                    url_analysis_service.analyse(
                        extracted_url
                    )
                )

                url_results.append(
                    url_result
                )
            
                domain_result = (
                    domain_verification_service.verify(
                        extracted_url
                    )
                )

                domain_result["url"] = extracted_url

                domain_results.append(
                    domain_result
                )

                _append_evidence_reference(
                    result,

                    evidence_id=(
                        url_result.get(
                            "evidence_id"
                        )
                    ),

                    ledger_id=(
                        url_result.get(
                            "ledger_id"
                        )
                    ),

                    module=(
                        url_result.get(
                            "module",
                            "URL Intelligence",
                        )
                    ),
                )

            except Exception:


                # URL intelligence is an additional modality.
                # A malformed URL or temporary URL feature
                # extraction failure must not destroy the
                # remaining communication analysis.

                continue

        # ====================================================
        # 6. Visual Intelligence
        # ====================================================

        visual_result = None

        if is_image:

            try:

                visual_result = (
                    visual_analysis_service.analyse(
                        communication.filepath,

                        input_reference=(
                            communication.filename
                        ),

                        content_type=(
                            communication.mime_type
                        ),

                        file_size_bytes=(
                            communication.filesize
                        ),
                    )
                )

                visual_evidence = (
                    visual_result.get(
                        "evidence"
                    )
                )

                visual_ledger_entry = (
                    visual_result.get(
                        "ledger_entry"
                    )
                )

                if visual_evidence is not None:

                    _append_evidence_reference(
                        result,

                        evidence_id=(
                            visual_evidence.evidence_id
                        ),

                        ledger_id=(
                            visual_ledger_entry.ledger_id
                            if visual_ledger_entry
                            is not None
                            else None
                        ),

                        module=(
                            visual_evidence.module
                        ),
                    )

            except Exception:

                # Visual analysis is an additional modality.
                # OCR/NLP/URL analysis can still produce a
                # valid communication-level result.

                visual_result = None

        # ====================================================
        # 7. Multimodal Model-Preserving Fusion
        # ====================================================



        fusion_result = (
            multimodal_fusion_service.fuse(
                nlp=result.nlp,

                visual_result=(
                    visual_result
                ),

                url_results=(
                    url_results
                ),

                domain_results=(
                    domain_results
                ),

                voice_authenticity=(
                    voice_authenticity
                ),

                intent_result=(
                    intent_result
                ),

            )
        )

        # ====================================================
        # 8. Apply Final Communication-Level Decision
        # ====================================================
        phishing_urls = []
        if fusion_result.decision != "Unknown":
            result.risk_score = (
                fusion_result.risk_score
           )

            result.risk_level = (
                fusion_result.risk_level
            )

            result.confidence = (
                fusion_result.confidence
            )

            result.summary = (
                fusion_result.summary
       )

        if (
            qr_result is not None
            and qr_result.get("qr_detected")
        ):
            qr_count = len(
                qr_result.get("qr_codes", [])
            )

            phishing_urls = [
                url
                for url in url_results
                if url.get("label") == "Phishing"
            ]

            if phishing_urls:
                result.summary += (
                    f" QR Intelligence detected "
                    f"{qr_count} QR code(s). "
                    f"URL Intelligence classified "
                    f"{len(phishing_urls)} decoded "
                    f"URL(s) as Phishing."
                )

        # ====================================================
        # 9. Build Entity-Specific STG Security Evidence
        # ====================================================
        #
        # URL Intelligence provides security evidence about
        # the URL entity itself.
        #
        # Example:
        #
        # Communication:
        #     Phishing
        #
        # Content URL:
        #     https://www.hdfcbank.com
        #
        # URL Intelligence:
        #     Legitimate
        #
        # STG:
        #     URL entity receives a Legitimate
        #     ENTITY_SECURITY observation.
        #
        # The communication's phishing classification is NOT
        # copied into the URL's reputation.
        # ====================================================

        entity_security_observations = (
            _build_stg_entity_security_observations(
                url_results
            )
        )

        # ====================================================
        # 10. Securities Trust Graph
        # ====================================================
        #
        # STG receives:
        #
        # - content entities
        # - communication-level risk as communication context
        # - EEL provenance
        # - URL-model entity-specific security observations
        #
        # Communication risk is historical context only.
        # Entity reputation is calculated exclusively from
        # entity-specific security observations.
        # ====================================================

        stg_result = None

        try:

            stg_entities = dict(result.entities or {})

            qr_payloads = []

            if qr_result and qr_result.get("qr_detected"):

                for qr in qr_result.get("qr_codes", []):
                    decoded_url = qr.get("decoded_url")
                    matching_url_result = next(
                        (
                            u
                            for u in url_results
                            if u.get("url") == decoded_url
                        ),
                        None,
                    )

                    qr_payloads.append({
                        "qr_id": qr.get("qr_id"),

                        "payload": qr.get("payload"),

                        "payload_type": qr.get("payload_type"),

                        "decoded_url": decoded_url,

                        "decoded_email": qr.get("decoded_email"),

                        "decoded_phone": qr.get("decoded_phone"),

                        "upi": qr.get("upi"),

                        "evidence_id": qr.get("evidence_id"),

                        "ledger_id": qr.get("ledger_id"),

                        "url_evidence_id": (
                            matching_url_result.get("evidence_id")
                            if matching_url_result
                            else None
                        ),

                        "url_ledger_id": (
                            matching_url_result.get("ledger_id")
                            if matching_url_result
                            else None
                        ),

                        "url_label": (
                            matching_url_result.get("label")
                            if matching_url_result
                            else None
                        ),
                    })

            stg_entities["qr_codes"] = qr_payloads

            stg_result = graph_engine.analyse(
                db=db,

                communication_id=(
                    communication.communication_id
                ),

                entities=(
                    stg_entities
                ),

                risk_level=(
                    result.risk_level
                ),

                risk_score=(
                    result.risk_score
                ),

                evidence_ids=list(
                    result.evidence_ids
                ),

                ledger_ids=list(
                    result.ledger_ids
                ),

                entity_security_observations=(
                    entity_security_observations
                ),
            )

        except Exception as exc:

            # STG is an enrichment and historical trust layer.
            #
            # Failure to persist/query graph intelligence must
            # not discard otherwise valid NLP/URL/visual
            # analysis or prevent FCP generation.
            #
            # graph_engine.analyse() performs its own rollback
            # if its transaction fails.
            stg_result = None

        # ====================================================
        # 11. Generate One Final Communication-Level FCP
        # ====================================================

        # ----------------------------------------------------
        # Determine Final Analysis Availability
        # ----------------------------------------------------
        #
        # The final FCP may be generated after text, URL and
        # visual analysis. Empty OCR alone therefore does not
        # imply unavailable analysis if another modality
        # successfully produced a security signal.
        # ----------------------------------------------------

        analysis_available = bool(
            (
                isinstance(extracted_text, str)
                and extracted_text.strip()
            )
            or result.nlp is not None
            or bool(url_results)
            or (
                qr_result
                and qr_result.get(
                    "qr_detected"
                )
            )
            or (
                isinstance(visual_result, dict)
                and bool(
                    visual_result.get("prediction")
                )
            )
            or (
                voice_authenticity is not None
                and voice_authenticity.available
            )
            or bool(result.findings)
        )

        # ----------------------------------------------------
        # AVE receives only explicitly supplied sender/channel
        # metadata.
        #
        # result.entities and STG reputation are intentionally
        # NOT used to infer sender authenticity.
        # ----------------------------------------------------

        result.passport = (
            trust_service.process(
                analysis=result,

                communication_id=(
                    communication.communication_id
                ),

                communication_type=(
                    result.document_type
                ),

                sender_email=(
                    sender_email
                ),

                sender_phone=(
                    sender_phone
                ),

                sender_website=(
                    sender_website
                ),

                claimed_sender=(
                    claimed_sender
                ),

                stg_result=(
                    stg_result
                ),
                voice_authenticity=(
                    voice_authenticity
                ),
                analysis_available=(
                    analysis_available
                ),
                trusted_hosting_platform=(
                    fusion_result.trusted_hosting_platform
                ),

                hosting_provider=(
                    fusion_result.hosting_provider
                ),
            )
        )

        # ====================================================
        # 12. Processing Time
        # ====================================================

        processing_time = (
            perf_counter()
            - start_time
        )

        # ====================================================
        # 13. Persist Final Analysis
        # ====================================================

        communication = update_analysis(
            db=db,
            communication=communication,
            result=result,
            processing_time=processing_time,
        )

        # ====================================================
        # 14. Persist Explainable Evidence Ledger
        # ====================================================
        #
        # Intelligence modules commit complete evidence records
        # to the central in-memory EEL during analysis.
        #
        # AnalysisResult stores only ledger/evidence references.
        # Resolve those references here and persist the complete
        # auditable entries against this communication.
        # ====================================================

        ledger_entries = []

        for ledger_id in result.ledger_ids:

            ledger_entry = (
                evidence_ledger.get(
                    ledger_id
                )
            )

            if ledger_entry is not None:

                ledger_entries.append(
                    ledger_entry
                )

        if ledger_entries:

            eel_persistence_service.persist_entries(
                db=db,

                communication_id=(
                    communication.communication_id
                ),

                ledger_entries=ledger_entries,
            )

        # ====================================================
        # 14. NLP Response
        # ====================================================

        nlp_response = None

        if result.nlp is not None:

            nlp_response = {
                "label":
                    result.nlp.label,

                "class_id":
                    result.nlp.class_id,

                "confidence":
                    result.nlp.confidence,

                "confidence_percent":
                    result.nlp.confidence_percent,

                "probabilities":
                    result.nlp.probabilities,

                "inference_time_ms":
                    result.nlp.inference_time_ms,

                "risk_score":
                    result.nlp.risk_score,

                "communication_text":
                    result.nlp.communication_text,
            }

        # ====================================================
        # 15. Visual Response
        # ====================================================

        visual_response = None

        if visual_result is not None:

            prediction = (
                visual_result["prediction"]
            )

            visual_response = {
                "label":
                    prediction["label"],

                "class_id":
                    prediction["class_id"],

                "confidence":
                    prediction["confidence"],

                "confidence_percent":
                    prediction[
                        "confidence_percent"
                    ],

                "phishing_probability":
                    prediction[
                        "phishing_probability"
                    ],

                "phishing_probability_percent":
                    prediction[
                        "phishing_probability_percent"
                    ],

                "legitimate_probability":
                    prediction[
                        "legitimate_probability"
                    ],

                "legitimate_probability_percent":
                    prediction[
                        "legitimate_probability_percent"
                    ],

                "risk_score":
                    prediction["risk_score"],

                "decision_threshold":
                    prediction[
                        "decision_threshold"
                    ],

                "inference_time_ms":
                    prediction[
                        "inference_time_ms"
                    ],

                "image_width":
                    visual_result[
                        "image_width"
                    ],

                "image_height":
                    visual_result[
                        "image_height"
                    ],
            }

        # ====================================================
        # 16. URL Response
        # ====================================================

        url_response = []

        for url_result in url_results:

            url_response.append(
                {
                    "url":
                        url_result["url"],

                    "label":
                        url_result["label"],

                    "class_id":
                        url_result["class_id"],

                    "confidence":
                        url_result["confidence"],

                    "confidence_percent":
                        url_result[
                            "confidence_percent"
                        ],

                    "phishing_probability":
                        url_result[
                            "phishing_probability"
                        ],

                    "phishing_probability_percent":
                        url_result[
                            "phishing_probability_percent"
                        ],

                    "legitimate_probability":
                        url_result[
                            "legitimate_probability"
                        ],

                    "legitimate_probability_percent":
                        url_result[
                            "legitimate_probability_percent"
                        ],

                    "risk_score":
                        url_result["risk_score"],

                    "inference_time_ms":
                        url_result[
                            "inference_time_ms"
                        ],

                    "model_info":
                        url_result["model_info"],

                    "explanation":
                        url_result["explanation"],

                    "evidence_id":
                        url_result["evidence_id"],

                    "ledger_id":
                        url_result["ledger_id"],
                }
            )

        # ====================================================
        # 17. Fusion Response
        # ====================================================

        fusion_response = (
            fusion_result.as_dict()
        )

        if qr_result is not None:
            for qr in qr_result.get(
                "qr_codes",
                [],
            ):
                decoded_url = qr.get(
                    "decoded_url"
                )

                if not decoded_url:
                    continue

                matching_url_result = next(
                    (
                        url
                        for url in url_results
                        if url.get("url") == decoded_url
                    ),
                    None,
                )

                qr["url_analysis"] = (
                    matching_url_result
                )

        # ====================================================
        # 18. STG Response
        # ====================================================

        stg_response = None

        if stg_result is not None:

            if hasattr(
                stg_result,
                "model_dump",
            ):

                stg_response = (
                    stg_result.model_dump(
                        mode="json"
                    )
                )

            elif hasattr(
                stg_result,
                "dict",
            ):

                stg_response = (
                    stg_result.dict()
                )

        # ====================================================
        # 19. Combined EEL References
        # ====================================================

        evidence_response = {
            "evidence_ids": list(
                result.evidence_ids
            ),

            "ledger_ids": list(
                result.ledger_ids
            ),

            "modules": list(
                result.evidence_modules
            ),
        }

        # ====================================================
        # Persist Rich Analysis Snapshot
        # ====================================================
        #
        # Preserve the detailed communication-level analysis
        # so GET /upload/{communication_id} can reconstruct
        # the same security context after process restart.
        #
        # STG itself remains persisted in its dedicated graph
        # tables. The FCP stores its contextual STG snapshot.
        # ====================================================

        communication.nlp_result = (
            nlp_response
        )

        communication.visual_result = (
            visual_response
        )

        communication.voice_result = (
            {
                "module": voice_result["module"],
                "communication_type": voice_result["communication_type"],
                "voice": voice_result["voice"],
                "analysis": {
                    "risk_score": result.risk_score,
                    "risk_level": result.risk_level,
                    "confidence": result.confidence,
                    "document_type": result.document_type,
                    "document_confidence": result.document_confidence,
                    "summary": result.summary,
                    "findings": result.findings,
                    "entities": result.entities,
                },
                "voice_authenticity": (
                    asdict(voice_authenticity)
                    if voice_authenticity is not None
                    else None
                ),
            }
            if voice_result is not None
            else None
        )

        communication.qr_result = (
            qr_result
        )

        communication.url_results = (
            url_response
        )

        communication.domain_verification = (
            domain_results
        )

        communication.multimodal_fusion = (
            fusion_response
        )

        communication.communication_intent = (
            intent_result
        )

        communication.evidence_references = (
            evidence_response
        )

        communication.passport = (
            result.passport.model_dump(
                mode="json"
            )
            if result.passport is not None
            else None
        )

        db.commit()

        db.refresh(
            communication
        )

        # ====================================================
        # 20. API Response
        # ====================================================

        analysis_response = {

            # --------------------------------------------
            # Final communication-level result
            # --------------------------------------------

            "risk_score":
                result.risk_score,

            "risk_level":
                result.risk_level,

            "confidence":
                result.confidence,

            # --------------------------------------------
            # Context
            # --------------------------------------------

            "document_type":
                result.document_type,

            "document_confidence":
                result.document_confidence,

            # --------------------------------------------
            # Explanation
            # --------------------------------------------

            "summary":
                result.summary,

            "findings":
                result.findings,

            "entities":
                result.entities,

            # --------------------------------------------
            # Trained model outputs
            # --------------------------------------------

            "nlp":
                nlp_response,

            "visual":
                visual_response,

            "voice": (
                {
                    **voice_result,
                    "voice_authenticity": (
                        asdict(voice_authenticity)
                        if voice_authenticity is not None
                        else None
                    ),
                }
                if voice_result is not None
                else None
            ),

            "qr": (
                {
                    "available": qr_result.get(
                        "qr_detected",
                        False,
                    ),

                    "count": len(
                        qr_result.get(
                            "qr_codes",
                            [],
                        )
                   ),

        # ----------------------------------------
        # Quick QR summary for frontend
        # ----------------------------------------

                    "contains_url": any(
                        code.get("decoded_url")
                        for code in qr_result.get(
                            "qr_codes",
                            [],
                        )
                    ),

                    "contains_email": any(
                        code.get("decoded_email")
                        for code in qr_result.get(
                            "qr_codes",
                            [],
                        )
                    ),

                    "contains_phone": any(
                        code.get("decoded_phone")
                        for code in qr_result.get(
                            "qr_codes",
                            [],
                        )
                    ),

                    "codes": qr_result.get(
                        "qr_codes",
                        [],
                    ),
                }
                if qr_result is not None
                else None
            ),

            "urls":
                url_response,

            "domain_verification":
                domain_results,

            # --------------------------------------------
            # Multimodal decision
            # --------------------------------------------

            "communication_intent": intent_result,

            "multimodal_fusion":
                fusion_response,

            # --------------------------------------------
            # Securities Trust Graph
            # --------------------------------------------

            "securities_trust_graph":
                stg_response,

            # --------------------------------------------
            # Combined Explainable Evidence Ledger
            # --------------------------------------------

            "evidence":
                evidence_response,

            # --------------------------------------------
            # Final FCP + AVE
            # --------------------------------------------

            "passport":
                result.passport,
        }

        return UploadResponse(

            upload={
                "communication_id":
                    communication.communication_id,

                "filename":
                    communication.filename,

                "file_type":
                    communication.file_type,

                "status":
                    communication.status,

                "uploaded_at":
                    communication.uploaded_at,
            },

            ocr={
                "status":
                    communication.ocr_status,

                "text_length":
                    len(
                        communication.extracted_text
                        or ""
                    ),
            },

            analysis=analysis_response,

            processing_time=round(
                communication.processing_time,
                2,
            ),
        )

    except HTTPException:
        raise

    except Exception as exc:
        db.rollback()
        if communication is not None:
            communication.status = "Failed"

            try:
                db.commit()
            except Exception:
                db.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    finally:

        if file is not None:

            await file.close()


# ============================================================
# Upload History
# ============================================================

@router.get(
    "/history",
    response_model=List[
        UploadHistoryResponse
    ],
    summary="Get upload history",
    description="""
Returns analysed communications with optional filtering.

Filters:
- risk_level
- document_type
- status
- filename

Supports pagination using skip and limit.
""",
)
def get_upload_history_endpoint(
    risk_level: str | None = Query(
        default=None,
        description=(
            "Filter by risk level "
            "(High, Medium, Low)"
        ),
    ),

    document_type: str | None = Query(
        default=None,
        description=(
            "Filter by detected document type"
        ),
    ),

    status: str | None = Query(
        default=None,
        description=(
            "Filter by processing status"
        ),
    ),

    filename: str | None = Query(
        default=None,
        description=(
            "Search filename (partial match)"
        ),
    ),

    skip: int = Query(
        default=0,
        ge=0,
        description=(
            "Number of records to skip"
        ),
    ),

    limit: int = Query(
        default=100,
        ge=1,
        le=500,
        description=(
            "Maximum number of records to return"
        ),
    ),

    db: Session = Depends(
        get_db
    ),
    current_user: User = Depends(
        get_current_user
    ),
):
    """
    Get communication history with optional filtering.
    """

    return get_upload_history(
        db=db,
        risk_level=risk_level,
        document_type=document_type,
        status=status,
        filename=filename,
        skip=skip,
        limit=limit,
    )


# ============================================================
# Communication Details
# ============================================================

@router.get(
    "/{communication_id}",
    response_model=DocumentResponse,
    summary="Get communication details",
    description=(
        "Returns the persisted extracted text and analysis "
        "results for a communication."
    ),
)
def get_document(
    communication_id: str,
    db: Session = Depends(
        get_db
    ),
    current_user: User = Depends(
        get_current_user
    )
):
    """
    Get a communication by communication ID.
    """

    communication = (
        get_communication_by_id(
            db,
            communication_id,
        )
    )

    if communication is None:

        raise HTTPException(
            status_code=404,
            detail="Communication not found",
        )

    return communication