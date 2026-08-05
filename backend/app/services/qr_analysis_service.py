"""
qr_analysis_service.py

SecureSense AI QR Intelligence service.

Pipeline
--------
Image
  ↓
OpenCV QR detection / decoding
  ↓
Payload classification
  ↓
Deterministic QR fingerprint
  ↓
Explainable Evidence Ledger (EEL)
  ↓
Structured QR Intelligence result

Security Boundary
-----------------
A QR code is an observed communication-content artifact.

QR decoding does NOT:
- authenticate the sender
- verify ownership of the decoded destination
- establish whether a decoded URL is legitimate or malicious

Decoded URL security classification remains the responsibility
of URL Intelligence.

Sender authentication remains the responsibility of AVE.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from time import perf_counter
from typing import Any
from urllib.parse import parse_qs, urlparse

import cv2

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
)
from app.eel.ledger import evidence_ledger


# ============================================================
# QR Intelligence Service
# ============================================================

class QRAnalysisService:
    """
    Detect, decode and persist auditable QR intelligence.
    """

    URL_PATTERN = re.compile(
        r"^https?://",
        re.IGNORECASE,
    )

    EMAIL_PATTERN = re.compile(
        r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$",
        re.IGNORECASE,
    )

    PHONE_PATTERN = re.compile(
        r"^\+?[0-9][0-9\s().-]{6,20}$"
    )

    # ========================================================
    # Public Analysis
    # ========================================================

    def analyse(
        self,
        image_path: str,
        *,
        input_reference: str | None = None,
        content_type: str | None = None,
        file_size_bytes: int | None = None,
    ) -> dict[str, Any]:
        """
        Detect and decode readable QR codes from an image and
        commit one auditable EEL record per decoded QR code.
        """

        started = perf_counter()

        path = Path(
            image_path
        )

        if not path.exists():
            raise FileNotFoundError(
                f"Image does not exist: {image_path}"
            )

        image = cv2.imread(
            str(path)
        )

        if image is None:
            raise ValueError(
                "OpenCV could not decode the supplied image."
            )

        height, width = image.shape[:2]

        raw_results = (
            self._detect_multiple(
                image
            )
        )

        # OpenCV's multi decoder can fail on otherwise
        # readable single-QR images, so preserve a fallback.

        if not raw_results:

            single_result = (
                self._detect_single(
                    image
                )
            )

            if single_result is not None:
                raw_results = [
                    single_result
                ]

        decoded_items = []

        seen_fingerprints = set()

        # Detection/decoding time is measured before evidence
        # persistence so the value describes QR processing.

        detection_elapsed_ms = (
            perf_counter()
            - started
        ) * 1000.0

        for raw_result in raw_results:

            payload = str(
                raw_result.get(
                    "payload",
                    ""
                )
            ).strip()

            if not payload:
                continue

            fingerprint = (
                self._fingerprint(
                    payload
                )
            )

            if fingerprint in seen_fingerprints:
                continue

            seen_fingerprints.add(
                fingerprint
            )

            payload_info = (
                self._classify_payload(
                    payload
                )
            )

            qr_item = {
                "qr_id":
                    fingerprint,

                "payload":
                    payload,

                "payload_type":
                    payload_info[
                        "payload_type"
                    ],

                "decoded_url":
                    payload_info.get(
                        "decoded_url"
                    ),

                "decoded_email":
                    payload_info.get(
                        "decoded_email"
                    ),

                "decoded_phone":
                    payload_info.get(
                        "decoded_phone"
                    ),

                "upi":
                    payload_info.get(
                        "upi"
                    ),

                "bounding_box":
                    raw_result.get(
                        "bounding_box"
                    ),

                "detected":
                    True,

                "decoded":
                    True,
            }

            # =================================================
            # EEL Evidence
            # =================================================
            #
            # This record proves:
            #
            # - a QR artifact was detected
            # - its payload was decoded
            # - its semantic payload type was identified
            # - the deterministic QR identity was generated
            #
            # It does NOT claim that the payload or sender is
            # legitimate, malicious, verified or authenticated.
            # =================================================

            evidence = EvidenceRecord(
                module="QR Intelligence",

                evidence_type=(
                    "QR_PAYLOAD_DECODE"
                ),

                input_reference=(
                    input_reference
                    or path.name
                ),

                prediction=(
                    payload_info[
                        "payload_type"
                    ]
                ),

                # QR payload classification here is
                # deterministic parsing, not a learned
                # classification class.
                class_id=None,

                # Successful OpenCV decoding is represented
                # separately from maliciousness probability.
                confidence=1.0,

                # QR decoding itself creates no security-risk
                # score. Destination risk is determined by
                # downstream security intelligence.
                risk_score=0.0,

                explanation=[],

                model_info=EvidenceModelInfo(
                    module=(
                        "QR Intelligence"
                    ),

                    model_type=(
                        "OpenCV QRCodeDetector"
                    ),

                    model_file=None,

                    feature_count=None,
                ),

                supporting_data={
                    "qr_id":
                        fingerprint,

                    "payload":
                        payload,

                    "payload_type":
                        payload_info[
                            "payload_type"
                        ],

                    "decoded_url":
                        payload_info.get(
                            "decoded_url"
                        ),

                    "decoded_email":
                        payload_info.get(
                            "decoded_email"
                        ),

                    "decoded_phone":
                        payload_info.get(
                            "decoded_phone"
                        ),

                    "upi":
                        payload_info.get(
                            "upi"
                        ),

                    "bounding_box":
                        raw_result.get(
                            "bounding_box"
                        ),

                    "image_width":
                        int(width),

                    "image_height":
                        int(height),

                    "content_type":
                        content_type,

                    "file_size_bytes":
                        file_size_bytes,

                    "decoder":
                        "OpenCV QRCodeDetector",

                    "decoder_version":
                        cv2.__version__,

                    "detected":
                        True,

                    "decoded":
                        True,

                    "inference_time_ms":
                        round(
                            detection_elapsed_ms,
                            4,
                        ),

                    "security_boundary": (
                        "QR decoding identifies communication "
                        "content only. It does not authenticate "
                        "the sender or determine destination "
                        "security."
                    ),
                },
            )

            ledger_entry = (
                evidence_ledger.record(
                    evidence
                )
            )

            qr_item[
                "evidence_id"
            ] = evidence.evidence_id

            qr_item[
                "ledger_id"
            ] = ledger_entry.ledger_id

            qr_item[
                "module"
            ] = "QR Intelligence"

            decoded_items.append(
                qr_item
            )

        elapsed_ms = (
            perf_counter()
            - started
        ) * 1000.0

        return {
            "module":
                "QR Intelligence",

            "qr_detected":
                bool(decoded_items),

            "qr_count":
                len(decoded_items),

            "image_width":
                int(width),

            "image_height":
                int(height),

            "inference_time_ms":
                round(
                    elapsed_ms,
                    4,
                ),

            "qr_codes":
                decoded_items,
        }

    # ========================================================
    # Multiple QR Detection
    # ========================================================

    def _detect_multiple(
        self,
        image,
    ) -> list[dict[str, Any]]:

        detector = (
            cv2.QRCodeDetector()
        )

        try:

            (
                detected,
                decoded_info,
                points,
                _,
            ) = detector.detectAndDecodeMulti(
                image
            )

        except Exception:

            return []

        if (
            not detected
            or not decoded_info
        ):
            return []

        results = []

        for index, payload in enumerate(
            decoded_info
        ):

            payload = str(
                payload or ""
            ).strip()

            if not payload:
                continue

            bounding_box = None

            if (
                points is not None
                and index < len(points)
            ):

                bounding_box = (
                    self._serialize_points(
                        points[index]
                    )
                )

            results.append(
                {
                    "payload":
                        payload,

                    "bounding_box":
                        bounding_box,
                }
            )

        return results

    # ========================================================
    # Single QR Detection
    # ========================================================

    def _detect_single(
        self,
        image,
    ) -> dict[str, Any] | None:

        detector = (
            cv2.QRCodeDetector()
        )

        try:

            (
                payload,
                points,
                _,
            ) = detector.detectAndDecode(
                image
            )

        except Exception:

            return None

        payload = str(
            payload or ""
        ).strip()

        if not payload:
            return None

        return {
            "payload":
                payload,

            "bounding_box":
                self._serialize_points(
                    points
                ),
        }

    # ========================================================
    # Payload Classification
    # ========================================================

    def _classify_payload(
        self,
        payload: str,
    ) -> dict[str, Any]:

        value = str(
            payload
        ).strip()

        lower_value = (
            value.lower()
        )

        # ----------------------------------------------------
        # URL
        # ----------------------------------------------------

        if self.URL_PATTERN.match(
            value
        ):

            return {
                "payload_type":
                    "URL",

                "decoded_url":
                    value,
            }

        # ----------------------------------------------------
        # UPI
        # ----------------------------------------------------

        if lower_value.startswith(
            "upi://"
        ):

            return {
                "payload_type":
                    "UPI",

                "upi":
                    self._parse_upi(
                        value
                    ),
            }

        # ----------------------------------------------------
        # Email URI
        # ----------------------------------------------------

        if lower_value.startswith(
            "mailto:"
        ):

            email = value[
                len("mailto:"):
            ].split(
                "?",
                1,
            )[0].strip()

            return {
                "payload_type":
                    "Email",

                "decoded_email":
                    email or None,
            }

        # ----------------------------------------------------
        # Telephone URI
        # ----------------------------------------------------

        if lower_value.startswith(
            "tel:"
        ):

            phone = value[
                len("tel:"):
            ].strip()

            return {
                "payload_type":
                    "Phone",

                "decoded_phone":
                    phone or None,
            }

        # ----------------------------------------------------
        # Plain Email
        # ----------------------------------------------------

        if self.EMAIL_PATTERN.fullmatch(
            value
        ):

            return {
                "payload_type":
                    "Email",

                "decoded_email":
                    value,
            }

        # ----------------------------------------------------
        # Plain Phone
        # ----------------------------------------------------

        if self.PHONE_PATTERN.fullmatch(
            value
        ):

            return {
                "payload_type":
                    "Phone",

                "decoded_phone":
                    value,
            }

        # ----------------------------------------------------
        # Other Text
        # ----------------------------------------------------

        return {
            "payload_type":
                "Text",
        }

    # ========================================================
    # UPI Parsing
    # ========================================================

    @staticmethod
    def _parse_upi(
        payload: str,
    ) -> dict[str, Any]:

        try:

            parsed = urlparse(
                payload
            )

            params = parse_qs(
                parsed.query
            )

        except Exception:

            return {
                "raw":
                    payload
            }

        def first(
            key: str,
        ) -> str | None:

            values = params.get(
                key
            )

            if not values:
                return None

            value = str(
                values[0]
            ).strip()

            return (
                value
                if value
                else None
            )

        return {
            "raw":
                payload,

            "payee_address":
                first("pa"),

            "payee_name":
                first("pn"),

            "merchant_code":
                first("mc"),

            "transaction_reference":
                first("tr"),

            "transaction_note":
                first("tn"),

            "amount":
                first("am"),

            "currency":
                first("cu"),
        }

    # ========================================================
    # Deterministic QR Identity
    # ========================================================

    @staticmethod
    def _fingerprint(
        payload: str,
    ) -> str:

        normalized = str(
            payload
        ).strip()

        digest = hashlib.sha256(
            normalized.encode(
                "utf-8"
            )
        ).hexdigest()

        return (
            f"QR-{digest[:24]}"
        )

    # ========================================================
    # Point Serialization
    # ========================================================

    @staticmethod
    def _serialize_points(
        points,
    ) -> list[
        dict[str, float]
    ] | None:

        if points is None:
            return None

        try:

            return [
                {
                    "x":
                        round(
                            float(point[0]),
                            4,
                        ),

                    "y":
                        round(
                            float(point[1]),
                            4,
                        ),
                }

                for point in points
            ]

        except Exception:

            return None


# ============================================================
# Singleton
# ============================================================

qr_analysis_service = (
    QRAnalysisService()
)