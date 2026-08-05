"""
visual_analysis_service.py

Reusable orchestration service for SecureSense AI
Visual Phishing Intelligence.

Pipeline:
    Website screenshot
        ↓
    Frozen ConvNeXt-Tiny
        ↓
    Visual phishing probability
        ↓
    Predicted-class Grad-CAM
        ↓
    Explainable Evidence Ledger (EEL)

This service does NOT generate the final communication-level
Financial Communication Passport. It returns the visual
prediction and its committed EEL evidence so that callers such
as /visual/analyse and /upload/ can decide how to compose the
final communication-level trust result.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Union

from PIL import Image

from app.eel.evidence_models import (
    EvidenceModelInfo,
    EvidenceRecord,
    VisualAttentionPoint,
    VisualEvidence,
)
from app.eel.ledger import evidence_ledger

from app.services.visual_explainability_service import (
    visual_explainability_service,
)
from app.services.visual_model_service import (
    visual_model_service,
)


class VisualAnalysisService:
    """
    Runs the complete reusable visual intelligence pipeline.

    Responsibilities:
    - ConvNeXt-Tiny inference
    - Predicted-class Grad-CAM
    - Prediction/explanation consistency validation
    - Visual EEL evidence creation
    - EEL commit

    FCP generation is intentionally left to the caller because
    /upload/ may combine NLP and visual evidence into one
    communication-level passport.
    """

    # ========================================================
    # Public analysis entry point
    # ========================================================

    def analyse(
        self,
        image: Union[
            Image.Image,
            str,
            Path,
        ],
        *,
        input_reference: Optional[str] = None,
        content_type: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
    ) -> Dict[str, Any]:

        should_close = False

        # ----------------------------------------------------
        # 1. Resolve image
        # ----------------------------------------------------

        if isinstance(
            image,
            (str, Path),
        ):

            image_path = Path(image)

            if not image_path.exists():

                raise FileNotFoundError(
                    f"Screenshot not found: {image_path}"
                )

            if not image_path.is_file():

                raise ValueError(
                    f"Screenshot path is not a file: "
                    f"{image_path}"
                )

            pil_image = Image.open(
                image_path
            )

            pil_image.load()

            should_close = True

            if input_reference is None:
                input_reference = (
                    image_path.name
                )

            if file_size_bytes is None:

                try:
                    file_size_bytes = (
                        image_path.stat().st_size
                    )

                except OSError:
                    file_size_bytes = None

        elif isinstance(
            image,
            Image.Image,
        ):

            pil_image = image

        else:

            raise TypeError(
                "image must be a PIL Image "
                "or filesystem path."
            )

        try:

            # ------------------------------------------------
            # 2. Standardise image representation
            # ------------------------------------------------

            rgb_image = pil_image.convert(
                "RGB"
            )

            image_width, image_height = (
                rgb_image.size
            )

            if (
                image_width <= 0
                or image_height <= 0
            ):

                raise ValueError(
                    "Invalid image dimensions."
                )

            # ------------------------------------------------
            # 3. Frozen ConvNeXt inference
            # ------------------------------------------------

            result = (
                visual_model_service.predict(
                    rgb_image
                )
            )

            # ------------------------------------------------
            # 4. Predicted-class Grad-CAM
            # ------------------------------------------------

            gradcam_result = (
                visual_explainability_service.explain(
                    rgb_image,
                    target_class=result[
                        "class_id"
                    ],
                )
            )

            # ------------------------------------------------
            # 5. Verify model / explanation consistency
            # ------------------------------------------------

            expected_target_probability = (
                result[
                    "phishing_probability"
                ]
                if result[
                    "class_id"
                ] == 1
                else result[
                    "legitimate_probability"
                ]
            )

            probability_delta = abs(
                float(
                    gradcam_result[
                        "target_probability"
                    ]
                )
                -
                float(
                    expected_target_probability
                )
            )

            if probability_delta > 1e-5:

                raise RuntimeError(
                    "Visual prediction and Grad-CAM "
                    "probabilities are inconsistent."
                )

            # ------------------------------------------------
            # 6. Build compact Grad-CAM evidence
            # ------------------------------------------------

            point = gradcam_result[
                "max_attention_point"
            ]

            visual_evidence = VisualEvidence(

                method=gradcam_result[
                    "method"
                ],

                target_class=gradcam_result[
                    "target_class"
                ],

                target_label=gradcam_result[
                    "target_label"
                ],

                target_probability=gradcam_result[
                    "target_probability"
                ],

                target_layer=gradcam_result[
                    "target_layer"
                ],

                image_width=image_width,

                image_height=image_height,

                mean_attention=gradcam_result[
                    "mean_attention"
                ],

                max_attention=gradcam_result[
                    "max_attention"
                ],

                high_attention_ratio=gradcam_result[
                    "high_attention_ratio"
                ],

                max_attention_point=(
                    VisualAttentionPoint(

                        x=point["x"],

                        y=point["y"],

                        x_normalized=point[
                            "x_normalized"
                        ],

                        y_normalized=point[
                            "y_normalized"
                        ],
                    )
                ),
            )

            # ------------------------------------------------
            # 7. Build EEL record
            # ------------------------------------------------

            model_info = result[
                "model_info"
            ]

            reference = (
                input_reference
                or "uploaded_image"
            )

            supporting_data: Dict[
                str,
                Any,
            ] = {

                "filename":
                    reference,

                "image_width":
                    image_width,

                "image_height":
                    image_height,

                "phishing_probability":
                    result[
                        "phishing_probability"
                    ],

                "phishing_probability_percent":
                    result[
                        "phishing_probability_percent"
                    ],

                "legitimate_probability":
                    result[
                        "legitimate_probability"
                    ],

                "legitimate_probability_percent":
                    result[
                        "legitimate_probability_percent"
                    ],

                "decision_threshold":
                    result[
                        "decision_threshold"
                    ],

                "gradcam_method":
                    gradcam_result[
                        "method"
                    ],

                "gradcam_target_class":
                    gradcam_result[
                        "target_class"
                    ],

                "gradcam_target_label":
                    gradcam_result[
                        "target_label"
                    ],

                "gradcam_target_probability":
                    gradcam_result[
                        "target_probability"
                    ],

                "gradcam_probability_delta":
                    probability_delta,

                "inference_time_ms":
                    result[
                        "inference_time_ms"
                    ],
            }

            if content_type is not None:

                supporting_data[
                    "content_type"
                ] = content_type

            if file_size_bytes is not None:

                supporting_data[
                    "file_size_bytes"
                ] = file_size_bytes

            evidence = EvidenceRecord(

                module=(
                    "Visual Phishing Intelligence"
                ),

                evidence_type=(
                    "VISUAL_PHISHING_CLASSIFICATION"
                ),

                input_reference=reference,

                prediction=result[
                    "label"
                ],

                class_id=result[
                    "class_id"
                ],

                confidence=result[
                    "confidence"
                ],

                # IMPORTANT:
                # This remains the trained visual model's
                # phishing probability × 100.
                risk_score=result[
                    "risk_score"
                ],

                visual_explanation=(
                    visual_evidence
                ),

                model_info=EvidenceModelInfo(

                    module=model_info.get(
                        "module",
                        "Visual Phishing Intelligence",
                    ),

                    model_type=model_info.get(
                        "model_type",
                        "ConvNeXt-Tiny",
                    ),

                    model_file=model_info.get(
                        "model_file"
                    ),

                    input_size=model_info.get(
                        "input_size"
                    ),

                    decision_threshold=result[
                        "decision_threshold"
                    ],
                ),

                supporting_data=(
                    supporting_data
                ),
            )

            # ------------------------------------------------
            # 8. Commit visual evidence to EEL
            # ------------------------------------------------

            ledger_entry = (
                evidence_ledger.record(
                    evidence
                )
            )

            # ------------------------------------------------
            # 9. Return reusable result
            # ------------------------------------------------

            return {

                "prediction":
                    result,

                "visual_explanation":
                    visual_evidence,

                "evidence":
                    evidence,

                "ledger_entry":
                    ledger_entry,

                "probability_delta":
                    probability_delta,

                "image_width":
                    image_width,

                "image_height":
                    image_height,
            }

        finally:

            # rgb_image may be a new PIL object created by
            # convert("RGB"). Close it when it is distinct
            # from the caller-owned image.

            if (
                "rgb_image" in locals()
                and rgb_image is not pil_image
            ):

                rgb_image.close()

            if should_close:

                pil_image.close()


# ============================================================
# Singleton
# ============================================================

visual_analysis_service = (
    VisualAnalysisService()
)