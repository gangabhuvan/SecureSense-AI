"""
visual_model_service.py

Production inference service for the frozen SecureSense AI
Visual Phishing Intelligence model.

Pipeline:
    Screenshot
        ↓
    RGB conversion
        ↓
    Resize to 224 × 224
        ↓
    ImageNet normalisation
        ↓
    Frozen ConvNeXt-Tiny
        ↓
    Phishing probability
        ↓
    Frozen threshold (0.555)
        ↓
    Visual phishing decision
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, Union

import torch
import torch.nn as nn

from PIL import Image

from torchvision import transforms
from torchvision.models import convnext_tiny


class VisualModelService:
    """
    Runs the frozen SecureSense AI visual phishing model.
    """

    def __init__(self) -> None:

        # ----------------------------------------------------
        # Paths
        # ----------------------------------------------------

        app_dir = Path(__file__).resolve().parents[1]

        self.model_dir = (
            app_dir
            / "ai"
            / "visual"
        )

        self.model_path = (
            self.model_dir
            / "visual_phishing_convnext_tiny.pth"
        )

        self.contract_path = (
            self.model_dir
            / "visual_model_contract.json"
        )

        # ----------------------------------------------------
        # Validate production artifacts
        # ----------------------------------------------------

        if not self.model_path.exists():

            raise FileNotFoundError(
                f"Visual phishing model not found: "
                f"{self.model_path}"
            )

        if not self.contract_path.exists():

            raise FileNotFoundError(
                f"Visual model contract not found: "
                f"{self.contract_path}"
            )

        # ----------------------------------------------------
        # Load production contract
        # ----------------------------------------------------

        with open(
            self.contract_path,
            "r",
            encoding="utf-8",
        ) as file:

            self.contract = json.load(file)

        # ----------------------------------------------------
        # Contract validation
        # ----------------------------------------------------

        if (
            self.contract.get("architecture")
            != "ConvNeXt-Tiny"
        ):

            raise RuntimeError(
                "Unexpected visual model architecture."
            )

        input_contract = self.contract["input"]
        output_contract = self.contract["output"]

        self.image_width = int(
            input_contract["width"]
        )

        self.image_height = int(
            input_contract["height"]
        )

        self.threshold = float(
            output_contract["decision_threshold"]
        )

        if (
            self.image_width != 224
            or self.image_height != 224
        ):

            raise RuntimeError(
                "Visual model must use 224×224 input."
            )

        if abs(
            self.threshold - 0.555
        ) > 1e-9:

            raise RuntimeError(
                "Unexpected production threshold. "
                f"Expected 0.555, found "
                f"{self.threshold}."
            )

        # ----------------------------------------------------
        # Device
        # ----------------------------------------------------

        self.device = torch.device(
            "cuda"
            if torch.cuda.is_available()
            else "cpu"
        )

        # ----------------------------------------------------
        # Preprocessing
        # EXACTLY matches frozen evaluation pipeline.
        # ----------------------------------------------------

        mean = input_contract[
            "normalization"
        ]["mean"]

        std = input_contract[
            "normalization"
        ]["std"]

        self.transform = transforms.Compose(
            [
                transforms.Resize(
                    (
                        self.image_height,
                        self.image_width,
                    )
                ),

                transforms.ToTensor(),

                transforms.Normalize(
                    mean=mean,
                    std=std,
                ),
            ]
        )

        # ----------------------------------------------------
        # Load production checkpoint
        # ----------------------------------------------------

        checkpoint = torch.load(
            self.model_path,
            map_location=self.device,
            weights_only=False,
        )

        # ----------------------------------------------------
        # Check checkpoint metadata
        # ----------------------------------------------------

        checkpoint_architecture = (
            checkpoint.get(
                "architecture"
            )
        )

        if (
            checkpoint_architecture
            != "ConvNeXt-Tiny"
        ):

            raise RuntimeError(
                "Checkpoint architecture mismatch."
            )

        checkpoint_threshold = float(
            checkpoint.get(
                "decision_threshold",
                self.threshold,
            )
        )

        if abs(
            checkpoint_threshold
            - self.threshold
        ) > 1e-9:

            raise RuntimeError(
                "Checkpoint threshold does not "
                "match visual_model_contract.json."
            )

        # ----------------------------------------------------
        # Build ConvNeXt-Tiny
        # ----------------------------------------------------

        self.model = convnext_tiny(
            weights=None
        )

        classifier_input = (
            self.model
            .classifier[2]
            .in_features
        )

        self.model.classifier[2] = nn.Linear(
            classifier_input,
            2,
        )

        # ----------------------------------------------------
        # Load frozen weights
        # ----------------------------------------------------

        state_dict = checkpoint.get(
            "model_state_dict"
        )

        if state_dict is None:

            raise RuntimeError(
                "Production checkpoint does not contain "
                "'model_state_dict'."
            )

        self.model.load_state_dict(
            state_dict,
            strict=True,
        )

        self.model = self.model.to(
            self.device
        )

        self.model.eval()

        # ----------------------------------------------------
        # Production metadata
        # ----------------------------------------------------

        self.model_info = {

            "module":
                "Visual Phishing Intelligence",

            "model_type":
                "ConvNeXt-Tiny",

            "model_file":
                self.model_path.name,

            "input_size":
                "224x224",

            "decision_threshold":
                self.threshold,

            "device":
                str(self.device),
        }

    # ========================================================
    # Prediction
    # ========================================================

    def predict(
        self,
        image: Union[
            Image.Image,
            str,
            Path,
        ],
    ) -> Dict[str, Any]:

        start = time.perf_counter()

        # ----------------------------------------------------
        # Load image
        # ----------------------------------------------------

        should_close = False

        if isinstance(
            image,
            (str, Path),
        ):

            image_path = Path(image)

            if not image_path.exists():

                raise FileNotFoundError(
                    f"Screenshot not found: "
                    f"{image_path}"
                )

            pil_image = Image.open(
                image_path
            )

            should_close = True

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
            # Exact production preprocessing
            # ------------------------------------------------

            pil_image = pil_image.convert(
                "RGB"
            )

            tensor = self.transform(
                pil_image
            )

            tensor = tensor.unsqueeze(
                0
            )

            tensor = tensor.to(
                self.device
            )

            # ------------------------------------------------
            # Frozen model inference
            # ------------------------------------------------

            with torch.inference_mode():

                logits = self.model(
                    tensor
                )

                probabilities = torch.softmax(
                    logits,
                    dim=1,
                )[0]

            legitimate_probability = float(
                probabilities[0].item()
            )

            phishing_probability = float(
                probabilities[1].item()
            )

            # ------------------------------------------------
            # Frozen production threshold
            # ------------------------------------------------

            predicted_class = int(
                phishing_probability
                >= self.threshold
            )

            label = (
                "Phishing"
                if predicted_class == 1
                else "Legitimate"
            )

            confidence = (
                phishing_probability
                if predicted_class == 1
                else legitimate_probability
            )

            risk_score = (
                phishing_probability
                * 100
            )

            inference_time_ms = (
                time.perf_counter()
                - start
            ) * 1000

            # ------------------------------------------------
            # Response
            # ------------------------------------------------

            return {

                "label":
                    label,

                "class_id":
                    predicted_class,

                "confidence":
                    round(
                        confidence,
                        6,
                    ),

                "confidence_percent":
                    round(
                        confidence * 100,
                        4,
                    ),

                "phishing_probability":
                    round(
                        phishing_probability,
                        6,
                    ),

                "phishing_probability_percent":
                    round(
                        phishing_probability * 100,
                        4,
                    ),

                "legitimate_probability":
                    round(
                        legitimate_probability,
                        6,
                    ),

                "legitimate_probability_percent":
                    round(
                        legitimate_probability * 100,
                        4,
                    ),

                "risk_score":
                    round(
                        risk_score,
                        2,
                    ),

                "decision_threshold":
                    self.threshold,

                "model_info":
                    self.model_info,

                "inference_time_ms":
                    round(
                        inference_time_ms,
                        2,
                    ),
            }

        finally:

            if should_close:

                pil_image.close()


# ============================================================
# Singleton
# ============================================================

visual_model_service = VisualModelService()