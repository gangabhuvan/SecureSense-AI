"""
report_service.py

SecureSense AI Security Investigation Report Service.

Generates a professional, read-only PDF security report from
persisted investigation data.

Important architecture
----------------------
Report generation NEVER reruns:
- OCR
- NLP inference
- URL intelligence
- visual intelligence
- multimodal fusion
- AVE
- STG analysis

The report represents the persisted investigation state and
its auditable evidence.

Security dimensions remain explicitly separated:

1. Communication Security
2. Sender Authenticity
3. Historical Entity Reputation
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


# ============================================================
# Helpers
# ============================================================

def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if hasattr(value, "model_dump"):
        try:
            return value.model_dump(mode="json")
        except TypeError:
            return value.model_dump()

    if hasattr(value, "dict"):
        return value.dict()

    return {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def _display(value: Any, default: str = "Not available") -> str:
    if value is None:
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    text = str(value).strip()

    return text if text else default


def _safe_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _percentage(
    value: Any,
    *,
    fraction: bool = False,
    default: str = "Not available",
) -> str:
    number = _safe_float(value)

    if number is None:
        return default

    if fraction:
        number *= 100.0

    return f"{number:.2f}%"


def _score(value: Any) -> str:
    number = _safe_float(value)

    if number is None:
        return "Not available"

    return f"{number:.2f}"


def _datetime_text(value: Any) -> str:
    if value is None:
        return "Not available"

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()

        if not text:
            return "Not available"

        try:
            dt = datetime.fromisoformat(
                text.replace("Z", "+00:00")
            )
        except ValueError:
            return text

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(
        timezone.utc
    ).strftime("%d %b %Y, %H:%M:%S UTC")


def _first(
    data: dict[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    for key in keys:
        value = data.get(key)

        if value is not None:
            return value

    return default


# ============================================================
# Report Service
# ============================================================

class ReportService:

    PAGE_WIDTH, PAGE_HEIGHT = A4

    NAVY = colors.HexColor("#0F172A")
    SLATE = colors.HexColor("#475569")
    MUTED = colors.HexColor("#64748B")
    BORDER = colors.HexColor("#E2E8F0")
    SOFT = colors.HexColor("#F8FAFC")
    BLUE = colors.HexColor("#2563EB")
    BLUE_SOFT = colors.HexColor("#EFF6FF")
    RED = colors.HexColor("#B91C1C")
    RED_SOFT = colors.HexColor("#FEF2F2")
    GREEN = colors.HexColor("#15803D")
    GREEN_SOFT = colors.HexColor("#F0FDF4")
    AMBER = colors.HexColor("#B45309")
    AMBER_SOFT = colors.HexColor("#FFFBEB")

    def __init__(self) -> None:
        base = getSampleStyleSheet()

        self.styles = {
            "title": ParagraphStyle(
                "SecureSenseTitle",
                parent=base["Title"],
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=self.NAVY,
                alignment=TA_LEFT,
                spaceAfter=4,
            ),

            "subtitle": ParagraphStyle(
                "SecureSenseSubtitle",
                parent=base["Normal"],
                fontName="Helvetica",
                fontSize=9.5,
                leading=14,
                textColor=self.MUTED,
                spaceAfter=10,
            ),

            "section": ParagraphStyle(
                "SecureSenseSection",
                parent=base["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=17,
                textColor=self.NAVY,
                spaceBefore=4,
                spaceAfter=8,
            ),

            "body": ParagraphStyle(
                "SecureSenseBody",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=9,
                leading=13.5,
                textColor=self.SLATE,
            ),

            "small": ParagraphStyle(
                "SecureSenseSmall",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.7,
                leading=10.5,
                textColor=self.MUTED,
            ),

            "label": ParagraphStyle(
                "SecureSenseLabel",
                parent=base["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=7.7,
                leading=10,
                textColor=self.MUTED,
            ),

            "value": ParagraphStyle(
                "SecureSenseValue",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=8.5,
                leading=11.5,
                textColor=self.NAVY,
            ),

            "value_bold": ParagraphStyle(
                "SecureSenseValueBold",
                parent=base["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=8.7,
                leading=11.5,
                textColor=self.NAVY,
            ),

            "center_small": ParagraphStyle(
                "SecureSenseCenterSmall",
                parent=base["BodyText"],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10,
                alignment=TA_CENTER,
                textColor=self.MUTED,
            ),
        }

    # ========================================================
    # Public API
    # ========================================================

    def generate(
        self,
        *,
        communication: Any,
        eel_entries: list[Any] | None = None,
        stg_observations: list[Any] | None = None,
    ) -> bytes:
        """
        Generate the persisted SecureSense investigation report.
        """

        eel_entries = eel_entries or []
        stg_observations = stg_observations or []

        buffer = BytesIO()

        doc = BaseDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=16 * mm,
            leftMargin=16 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=(
                "SecureSense AI Security Investigation Report"
            ),
            author="SecureSense AI",
            subject=(
                "Explainable multimodal security investigation"
            ),
        )

        frame = Frame(
            doc.leftMargin,
            doc.bottomMargin,
            doc.width,
            doc.height,
            id="normal",
        )

        template = PageTemplate(
            id="SecureSenseReport",
            frames=[frame],
            onPage=self._draw_page,
        )

        doc.addPageTemplates([template])

        story: list[Any] = []

        passport = _as_dict(
            getattr(
                communication,
                "passport",
                None,
            )
        )

        nlp = _as_dict(
            getattr(
                communication,
                "nlp_result",
                None,
            )
        )

        visual = _as_dict(
            getattr(
                communication,
                "visual_result",
                None,
            )
        )

        urls = _as_list(
            getattr(
                communication,
                "url_results",
                None,
            )
        )

        fusion = _as_dict(
            getattr(
                communication,
                "multimodal_fusion",
                None,
            )
        )

        evidence_refs = _as_dict(
            getattr(
                communication,
                "evidence_references",
                None,
            )
        )

        self._build_header(
            story,
            communication,
            passport,
        )

        self._build_executive_assessment(
            story,
            communication,
            passport,
            fusion,
        )

        self._build_passport(
            story,
            passport,
        )

        self._build_authenticity(
            story,
            passport,
        )

        self._build_multimodal(
            story,
            nlp,
            visual,
            urls,
            fusion,
        )

        self._build_stg(
            story,
            passport,
            stg_observations,
        )

        self._build_eel(
            story,
            eel_entries,
            evidence_refs,
        )

        self._build_conclusion(
            story,
            passport,
        )

        self._build_disclaimer(
            story
        )

        doc.build(story)

        pdf = buffer.getvalue()

        buffer.close()

        return pdf

    # ========================================================
    # Page Header / Footer
    # ========================================================

    def _draw_page(
        self,
        canvas,
        doc,
    ) -> None:

        canvas.saveState()

        canvas.setStrokeColor(
            self.BORDER
        )

        canvas.setLineWidth(0.5)

        canvas.line(
            doc.leftMargin,
            13 * mm,
            self.PAGE_WIDTH - doc.rightMargin,
            13 * mm,
        )

        canvas.setFillColor(
            self.MUTED
        )

        canvas.setFont(
            "Helvetica",
            7,
        )

        canvas.drawString(
            doc.leftMargin,
            8 * mm,
            "SecureSense AI · Trust Intelligence Platform",
        )

        canvas.drawRightString(
            self.PAGE_WIDTH - doc.rightMargin,
            8 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()

    # ========================================================
    # Header
    # ========================================================

    def _build_header(
        self,
        story,
        communication,
        passport,
    ) -> None:

        story.append(
            Paragraph(
                "SECURESENSE AI",
                ParagraphStyle(
                    "brand",
                    parent=self.styles["label"],
                    fontSize=8,
                    textColor=self.BLUE,
                    spaceAfter=4,
                ),
            )
        )

        story.append(
            Paragraph(
                "Security Investigation Report",
                self.styles["title"],
            )
        )

        story.append(
            Paragraph(
                (
                    "Persisted multimodal trust-intelligence "
                    "assessment with explainable evidence and "
                    "audit provenance."
                ),
                self.styles["subtitle"],
            )
        )

        rows = [
            [
                "Communication ID",
                _display(
                    getattr(
                        communication,
                        "communication_id",
                        None,
                    )
                ),
            ],
            [
                "Passport ID",
                _display(
                    passport.get(
                        "passport_id"
                    )
                ),
            ],
            [
                "Input",
                _display(
                    getattr(
                        communication,
                        "filename",
                        None,
                    )
                ),
            ],
            [
                "Status",
                _display(
                    getattr(
                        communication,
                        "status",
                        None,
                    )
                ),
            ],
            [
                "Submitted",
                _datetime_text(
                    getattr(
                        communication,
                        "uploaded_at",
                        None,
                    )
                ),
            ],
            [
                "Report Generated",
                _datetime_text(
                    datetime.now(
                        timezone.utc
                    )
                ),
            ],
        ]

        story.append(
            self._key_value_table(rows)
        )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # Executive Assessment
    # ========================================================

    def _build_executive_assessment(
        self,
        story,
        communication,
        passport,
        fusion,
    ) -> None:

        self._section(
            story,
            "1. Executive Security Assessment",
        )

        risk_level = _first(
            passport,
            "risk_level",
            default=getattr(
                communication,
                "risk_level",
                None,
            ),
        )

        risk_score = _first(
            passport,
            "risk_score",
            default=getattr(
                communication,
                "risk_score",
                None,
            ),
        )

        confidence = _first(
            passport,
            "confidence",
            default=getattr(
                communication,
                "confidence",
                None,
            ),
        )

        decision = _first(
            fusion,
            "decision",
            "label",
            "classification",
            default="Unknown",
        )

        rows = [
            [
                "Final AI Decision",
                _display(decision),
            ],
            [
                "Risk Level",
                _display(risk_level),
            ],
            [
                "Risk Score",
                _score(risk_score),
            ],
            [
                "Trust Score",
                _score(
                    passport.get(
                        "trust_score"
                    )
                ),
            ],
            [
                "Confidence",
                _percentage(
                    confidence
                ),
            ],
            [
                "Sender Verified",
                _display(
                    passport.get(
                        "verified_sender"
                    )
                ),
            ],
        ]

        story.append(
            self._key_value_table(rows)
        )

        recommendation = passport.get(
            "recommended_action"
        )

        if recommendation:

            story.append(
                Spacer(1, 8)
            )

            story.append(
                self._callout(
                    "Recommended Action",
                    str(recommendation),
                    self.RED_SOFT
                    if str(
                        risk_level
                    ).lower() == "high"
                    else self.BLUE_SOFT,
                )
            )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # FCP
    # ========================================================

    def _build_passport(
        self,
        story,
        passport,
    ) -> None:

        self._section(
            story,
            "2. Financial Communication Passport",
        )

        if not passport:

            story.append(
                Paragraph(
                    "No persisted Financial Communication "
                    "Passport is available for this investigation.",
                    self.styles["body"],
                )
            )

            story.append(
                Spacer(1, 12)
            )

            return

        rows = [
            [
                "Passport ID",
                _display(
                    passport.get(
                        "passport_id"
                    )
                ),
            ],
            [
                "Generated At",
                _datetime_text(
                    passport.get(
                        "generated_at"
                    )
                ),
            ],
            [
                "Communication Type",
                _display(
                    passport.get(
                        "communication_type"
                    )
                ),
            ],
            [
                "Claimed Sender",
                _display(
                    passport.get(
                        "claimed_sender"
                    )
                ),
            ],
            [
                "Verified Sender",
                _display(
                    passport.get(
                        "verified_sender"
                    )
                ),
            ],
            [
                "Risk / Trust",
                (
                    f"{_score(passport.get('risk_score'))} / "
                    f"{_score(passport.get('trust_score'))}"
                ),
            ],
        ]

        story.append(
            self._key_value_table(rows)
        )

        categories = _as_list(
            passport.get(
                "threat_categories"
            )
        )

        manipulation = _as_list(
            passport.get(
                "ai_manipulation_findings"
            )
        )

        if categories:

            story.append(
                Spacer(1, 8)
            )

            self._list_block(
                story,
                "Threat Categories",
                categories,
            )

        if manipulation:

            story.append(
                Spacer(1, 6)
            )

            self._list_block(
                story,
                "AI Manipulation Findings",
                manipulation,
            )

        evidence = _as_dict(
            passport.get(
                "evidence"
            )
        )

        if evidence:

            story.append(
                Spacer(1, 8)
            )

            evidence_rows = [
                [
                    "Total Findings",
                    _display(
                        evidence.get(
                            "total_findings"
                        )
                    ),
                ],
                [
                    "High Severity",
                    _display(
                        evidence.get(
                            "high_severity"
                        )
                    ),
                ],
                [
                    "Medium Severity",
                    _display(
                        evidence.get(
                            "medium_severity"
                        )
                    ),
                ],
                [
                    "Low Severity",
                    _display(
                        evidence.get(
                            "low_severity"
                        )
                    ),
                ],
                [
                    "Evidence Modules",
                    ", ".join(
                        map(
                            str,
                            _as_list(
                                evidence.get(
                                    "modules"
                                )
                            ),
                        )
                    )
                    or "Not available",
                ],
            ]

            story.append(
                self._key_value_table(
                    evidence_rows
                )
            )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # Authenticity
    # ========================================================

    def _build_authenticity(
        self,
        story,
        passport,
    ) -> None:

        self._section(
            story,
            "3. Sender Authenticity Verification",
        )

        verification = _as_dict(
            passport.get(
                "verification"
            )
        )

        if not verification:

            story.append(
                Paragraph(
                    "No persisted Authenticity Verification "
                    "Engine result is available.",
                    self.styles["body"],
                )
            )

            story.append(
                Spacer(1, 12)
            )

            return

        rows = [
            [
                "AVE Status",
                _display(
                    verification.get(
                        "status"
                    )
                ),
            ],
            [
                "Verification Confidence",
                _percentage(
                    verification.get(
                        "verification_confidence"
                    )
                ),
            ],
            [
                "Official Domain",
                _display(
                    verification.get(
                        "official_domain"
                    )
                ),
            ],
            [
                "Official Email",
                _display(
                    verification.get(
                        "official_email"
                    )
                ),
            ],
            [
                "Official Phone",
                _display(
                    verification.get(
                        "official_phone"
                    )
                ),
            ],
            [
                "Official QR",
                _display(
                    verification.get(
                        "official_qr"
                    )
                ),
            ],
            [
                "Digital Signature",
                _display(
                    verification.get(
                        "digital_signature"
                    )
                ),
            ],
            [
                "Metadata Consistent",
                _display(
                    verification.get(
                        "metadata_consistent"
                    )
                ),
            ],
        ]

        story.append(
            self._key_value_table(rows)
        )

        story.append(
            Spacer(1, 7)
        )

        story.append(
            self._callout(
                "Interpretation Boundary",
                (
                    "Sender authenticity is evaluated independently "
                    "from communication security and historical "
                    "entity reputation. A trusted URL or STG entity "
                    "does not independently authenticate the sender."
                ),
                self.BLUE_SOFT,
            )
        )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # Multimodal Intelligence
    # ========================================================

    def _build_multimodal(
        self,
        story,
        nlp,
        visual,
        urls,
        fusion,
    ) -> None:

        self._section(
            story,
            "4. Multimodal Intelligence",
        )

        if fusion:

            story.append(
                Paragraph(
                    "<b>Multimodal Fusion</b>",
                    self.styles["body"],
                )
            )

            fusion_rows = [
                [
                    "Decision",
                    _display(
                        _first(
                            fusion,
                            "decision",
                            "label",
                            "classification",
                        )
                    ),
                ],
                [
                    "Risk Level",
                    _display(
                        fusion.get(
                            "risk_level"
                        )
                    ),
                ],
                [
                    "Risk Score",
                    _score(
                        fusion.get(
                            "risk_score"
                        )
                    ),
                ],
                [
                    "Confidence",
                    _percentage(
                        fusion.get(
                            "confidence"
                        )
                    ),
                ],
                [
                    "Summary",
                    _display(
                        fusion.get(
                            "summary"
                        )
                    ),
                ],
            ]

            story.append(
                self._key_value_table(
                    fusion_rows
                )
            )

            story.append(
                Spacer(1, 8)
            )

        if nlp:

            story.append(
                Paragraph(
                    "<b>NLP Intelligence</b>",
                    self.styles["body"],
                )
            )

            nlp_rows = [
                [
                    "Prediction",
                    _display(
                        nlp.get(
                            "label"
                        )
                    ),
                ],
                [
                    "Confidence",
                    _percentage(
                        _first(
                            nlp,
                            "confidence_percent",
                            default=(
                                (
                                    _safe_float(
                                        nlp.get(
                                            "confidence"
                                        )
                                    )
                                    or 0.0
                                )
                                * 100.0
                            ),
                        )
                    ),
                ],
                [
                    "Risk Score",
                    _score(
                        nlp.get(
                            "risk_score"
                        )
                    ),
                ],
                [
                    "Inference Time",
                    (
                        f"{_score(nlp.get('inference_time_ms'))} ms"
                    ),
                ],
            ]

            story.append(
                self._key_value_table(
                    nlp_rows
                )
            )

            story.append(
                Spacer(1, 8)
            )

        if visual:

            story.append(
                Paragraph(
                    "<b>Visual Intelligence</b>",
                    self.styles["body"],
                )
            )

            visual_rows = [
                [
                    "Prediction",
                    _display(
                        visual.get(
                            "label"
                        )
                    ),
                ],
                [
                    "Confidence",
                    _percentage(
                        visual.get(
                            "confidence_percent"
                        )
                    ),
                ],
                [
                    "Phishing Probability",
                    _percentage(
                        visual.get(
                            "phishing_probability_percent"
                        )
                    ),
                ],
                [
                    "Risk Score",
                    _score(
                        visual.get(
                            "risk_score"
                        )
                    ),
                ],
                [
                    "Image Dimensions",
                    (
                        f"{_display(visual.get('image_width'))}"
                        " × "
                        f"{_display(visual.get('image_height'))}"
                    ),
                ],
                [
                    "Inference Time",
                    (
                        f"{_score(visual.get('inference_time_ms'))} ms"
                    ),
                ],
            ]

            story.append(
                self._key_value_table(
                    visual_rows
                )
            )

            story.append(
                Spacer(1, 8)
            )

        if urls:

            story.append(
                Paragraph(
                    "<b>URL Intelligence</b>",
                    self.styles["body"],
                )
            )

            for index, raw_url in enumerate(
                urls,
                start=1,
            ):

                url = _as_dict(
                    raw_url
                )

                url_rows = [
                    [
                        f"URL {index}",
                        _display(
                            url.get(
                                "url"
                            )
                        ),
                    ],
                    [
                        "Prediction",
                        _display(
                            url.get(
                                "label"
                            )
                        ),
                    ],
                    [
                        "Confidence",
                        _percentage(
                            url.get(
                                "confidence_percent"
                            )
                        ),
                    ],
                    [
                        "Phishing Probability",
                        _percentage(
                            url.get(
                                "phishing_probability_percent"
                            )
                        ),
                    ],
                    [
                        "Risk Score",
                        _score(
                            url.get(
                                "risk_score"
                            )
                        ),
                    ],
                    [
                        "Evidence ID",
                        _display(
                            url.get(
                                "evidence_id"
                            )
                        ),
                    ],
                    [
                        "Ledger ID",
                        _display(
                            url.get(
                                "ledger_id"
                            )
                        ),
                    ],
                ]

                story.append(
                    self._key_value_table(
                        url_rows
                    )
                )

                story.append(
                    Spacer(1, 6)
                )

        if (
            not fusion
            and not nlp
            and not visual
            and not urls
        ):

            story.append(
                Paragraph(
                    "No persisted multimodal intelligence "
                    "results are available.",
                    self.styles["body"],
                )
            )

        story.append(
            Spacer(1, 10)
        )

    # ========================================================
    # STG
    # ========================================================

    def _build_stg(
        self,
        story,
        passport,
        observations,
    ) -> None:

        self._section(
            story,
            "5. Securities Trust Graph",
        )

        stg = _as_dict(
            passport.get(
                "securities_trust_graph"
            )
        )

        if not stg:

            story.append(
                Paragraph(
                    "No Securities Trust Graph context is "
                    "available for this investigation.",
                    self.styles["body"],
                )
            )

            story.append(
                Spacer(1, 12)
            )

            return

        rows = [
            [
                "Available",
                _display(
                    stg.get(
                        "available"
                    )
                ),
            ],
            [
                "Historical Reputation Available",
                _display(
                    stg.get(
                        "reputation_available"
                    )
                ),
            ],
            [
                "Classification",
                _display(
                    stg.get(
                        "classification"
                    )
                ),
            ],
            [
                "Graph Risk Score",
                _score(
                    stg.get(
                        "graph_risk_score"
                    )
                ),
            ],
            [
                "Graph Trust Score",
                _score(
                    stg.get(
                        "graph_trust_score"
                    )
                ),
            ],
            [
                "Confidence",
                _percentage(
                    stg.get(
                        "confidence"
                    )
                ),
            ],
            [
                "Entities Analysed",
                _display(
                    stg.get(
                        "entities_analysed"
                    )
                ),
            ],
        ]

        story.append(
            self._key_value_table(rows)
        )

        summary = stg.get(
            "summary"
        )

        if summary:

            story.append(
                Spacer(1, 7)
            )

            story.append(
                Paragraph(
                    str(summary),
                    self.styles["body"],
                )
            )

        relationship = _as_dict(
            stg.get(
                "relationship_context"
            )
        )

        if relationship:

            story.append(
                Spacer(1, 8)
            )

            story.append(
                Paragraph(
                    "<b>Relationship-Derived Context</b>",
                    self.styles["body"],
                )
            )

            relationship_rows = [
                [
                    "Available",
                    _display(
                        relationship.get(
                            "available"
                        )
                    ),
                ],
                [
                    "Contexts Analysed",
                    _display(
                        relationship.get(
                            "contexts_analysed"
                        )
                    ),
                ],
                [
                    "Contexts Available",
                    _display(
                        relationship.get(
                            "contexts_available"
                        )
                    ),
                ],
                [
                    "Total Signals",
                    _display(
                        relationship.get(
                            "total_signals"
                        )
                    ),
                ],
            ]

            story.append(
                self._key_value_table(
                    relationship_rows
                )
            )

        if observations:

            story.append(
                Spacer(1, 8)
            )

            story.append(
                Paragraph(
                    (
                        "<b>Persisted STG Observations:</b> "
                        f"{len(observations)} observation(s) "
                        "are associated with this communication."
                    ),
                    self.styles["body"],
                )
            )

        story.append(
            Spacer(1, 7)
        )

        story.append(
            self._callout(
                "STG Interpretation Boundary",
                (
                    _display(
                        stg.get(
                            "contextual_role"
                        ),
                        (
                            "Historical entity context only. "
                            "Does not authenticate the sender or "
                            "override communication-level "
                            "security analysis."
                        ),
                    )
                ),
                self.BLUE_SOFT,
            )
        )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # EEL
    # ========================================================

    def _build_eel(
        self,
        story,
        eel_entries,
        evidence_refs,
    ) -> None:

        self._section(
            story,
            "6. Explainable Evidence Ledger",
        )

        if eel_entries:

            for index, entry in enumerate(
                eel_entries,
                start=1,
            ):

                data = (
                    _as_dict(entry)
                    or {
                        key: getattr(
                            entry,
                            key,
                            None,
                        )
                        for key in (
                            "ledger_id",
                            "evidence_id",
                            "module",
                            "evidence_type",
                            "prediction",
                            "confidence",
                            "risk_score",
                            "recorded_at",
                        )
                    }
                )

                rows = [
                    [
                        f"Evidence Record {index}",
                        _display(
                            data.get(
                                "module"
                            )
                        ),
                    ],
                    [
                        "Evidence ID",
                        _display(
                            data.get(
                                "evidence_id"
                            )
                        ),
                    ],
                    [
                        "Ledger ID",
                        _display(
                            data.get(
                                "ledger_id"
                            )
                        ),
                    ],
                    [
                        "Evidence Type",
                        _display(
                            data.get(
                                "evidence_type"
                            )
                        ),
                    ],
                    [
                        "Prediction",
                        _display(
                            data.get(
                                "prediction"
                            )
                        ),
                    ],
                    [
                        "Confidence",
                        _percentage(
                            data.get(
                                "confidence"
                            ),
                            fraction=True,
                        ),
                    ],
                    [
                        "Risk Score",
                        _score(
                            data.get(
                                "risk_score"
                            )
                        ),
                    ],
                    [
                        "Recorded At",
                        _datetime_text(
                            _first(
                                data,
                                "recorded_at",
                                "timestamp",
                            )
                        ),
                    ],
                ]

                story.append(
                    KeepTogether(
                        [
                            self._key_value_table(
                                rows
                            ),
                            Spacer(1, 7),
                        ]
                    )
                )

        else:

            modules = _as_list(
                evidence_refs.get(
                    "modules"
                )
            )

            evidence_ids = _as_list(
                evidence_refs.get(
                    "evidence_ids"
                )
            )

            ledger_ids = _as_list(
                evidence_refs.get(
                    "ledger_ids"
                )
            )

            rows = [
                [
                    "Evidence Records",
                    _display(
                        len(
                            evidence_ids
                        )
                    ),
                ],
                [
                    "Ledger References",
                    _display(
                        len(
                            ledger_ids
                        )
                    ),
                ],
                [
                    "Modules",
                    ", ".join(
                        map(
                            str,
                            modules,
                        )
                    )
                    or "Not available",
                ],
            ]

            story.append(
                self._key_value_table(rows)
            )

        story.append(
            Spacer(1, 7)
        )

        story.append(
            self._callout(
                "Audit Provenance",
                (
                    "This report references persisted SecureSense "
                    "evidence generated during the original "
                    "investigation. Report generation does not "
                    "rerun the underlying AI models."
                ),
                self.GREEN_SOFT,
            )
        )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # Conclusion
    # ========================================================

    def _build_conclusion(
        self,
        story,
        passport,
    ) -> None:

        self._section(
            story,
            "7. Investigation Conclusion",
        )

        recommendation = passport.get(
            "recommended_action"
        )

        if recommendation:

            story.append(
                Paragraph(
                    str(recommendation),
                    self.styles["body"],
                )
            )

        else:

            story.append(
                Paragraph(
                    (
                        "No final persisted recommendation is "
                        "available for this investigation."
                    ),
                    self.styles["body"],
                )
            )

        story.append(
            Spacer(1, 12)
        )

    # ========================================================
    # Disclaimer
    # ========================================================

    def _build_disclaimer(
        self,
        story,
    ) -> None:

        self._section(
            story,
            "Report Interpretation",
        )

        story.append(
            Paragraph(
                (
                    "SecureSense AI provides security decision-support "
                    "intelligence. Communication-level AI classification, "
                    "sender authenticity verification and historical "
                    "Securities Trust Graph reputation are independent "
                    "security dimensions. A legitimate URL, trusted graph "
                    "entity or verified metadata signal must not be "
                    "interpreted as proof that suspicious communication "
                    "content is safe. Where authenticity information is "
                    "unavailable, users should independently verify "
                    "sensitive financial instructions through official "
                    "channels."
                ),
                self.styles["small"],
            )
        )

    # ========================================================
    # UI Components
    # ========================================================

    def _section(
        self,
        story,
        title: str,
    ) -> None:

        story.append(
            Paragraph(
                title,
                self.styles["section"],
            )
        )

    def _key_value_table(
        self,
        rows: list[list[Any]],
    ) -> Table:

        data = []

        for label, value in rows:

            data.append(
                [
                    Paragraph(
                        _display(label),
                        self.styles["label"],
                    ),
                    Paragraph(
                        _display(value),
                        self.styles["value"],
                    ),
                ]
            )

        table = Table(
            data,
            colWidths=[
                48 * mm,
                125 * mm,
            ],
            hAlign="LEFT",
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, -1),
                        self.SOFT,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        self.BORDER,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ]
            )
        )

        return table

    def _callout(
        self,
        title: str,
        text: str,
        background,
    ) -> Table:

        content = Paragraph(
            (
                f"<b>{title}</b><br/>"
                f"{text}"
            ),
            self.styles["body"],
        )

        table = Table(
            [[content]],
            colWidths=[
                173 * mm
            ],
        )

        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        background,
                    ),
                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        self.BORDER,
                    ),
                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        9,
                    ),
                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        8,
                    ),
                ]
            )
        )

        return table

    def _list_block(
        self,
        story,
        title: str,
        values: list[Any],
    ) -> None:

        story.append(
            Paragraph(
                f"<b>{title}</b>",
                self.styles["body"],
            )
        )

        for value in values:

            story.append(
                Paragraph(
                    f"• {_display(value)}",
                    self.styles["body"],
                )
            )


# ============================================================
# Singleton
# ============================================================

report_service = ReportService()