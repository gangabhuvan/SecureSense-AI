"""
visual_explainability_service.py

Grad-CAM explainability service for the frozen SecureSense AI
ConvNeXt-Tiny Visual Phishing Intelligence model.

The service reuses the already-loaded production model from
visual_model_service. It DOES NOT load a second ConvNeXt model.

Pipeline:
    Screenshot
        ↓
    Frozen ConvNeXt-Tiny
        ↓
    Final convolutional feature representation
        ↓
    Grad-CAM
        ↓
    Normalised visual attention heatmap
"""

from typing import Any, Dict

import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image

from app.services.visual_model_service import (
    visual_model_service,
)


class VisualExplainabilityService:
    """
    Generates Grad-CAM explanations for the frozen
    ConvNeXt-Tiny visual phishing model.
    """

    def __init__(self) -> None:

        # Reuse production model.
        self.model_service = (
            visual_model_service
        )

        self.model = (
            self.model_service.model
        )

        self.device = (
            self.model_service.device
        )

        self.transform = (
            self.model_service.transform
        )

        # ----------------------------------------------------
        # ConvNeXt-Tiny target layer
        #
        # features[7] is the final ConvNeXt stage.
        # We hook its final CNBlock.
        # ----------------------------------------------------

        self.target_layer = (
            self.model.features[7][-1]
        )

        self.activations = None
        self.gradients = None

        self._forward_handle = (
            self.target_layer.register_forward_hook(
                self._forward_hook
            )
        )

        self._backward_handle = (
            self.target_layer.register_full_backward_hook(
                self._backward_hook
            )
        )

    # ========================================================
    # Hooks
    # ========================================================

    def _forward_hook(
        self,
        module,
        inputs,
        output,
    ) -> None:

        self.activations = (
            output.detach()
        )

    def _backward_hook(
        self,
        module,
        grad_input,
        grad_output,
    ) -> None:

        self.gradients = (
            grad_output[0].detach()
        )

    # ========================================================
    # Grad-CAM
    # ========================================================

    def explain(
        self,
        image: Image.Image,
        target_class: int = 1,
    ) -> Dict[str, Any]:
        """
        Generate Grad-CAM for the supplied screenshot.

        target_class=1 explains evidence influencing the
        phishing class.

        Returns numerical heatmap information only.
        Rendering/overlay is handled separately.
        """

        if not isinstance(
            image,
            Image.Image,
        ):

            raise TypeError(
                "image must be a PIL Image."
            )

        if target_class not in (0, 1):

            raise ValueError(
                "target_class must be 0 "
                "(Legitimate) or 1 (Phishing)."
            )

        # ----------------------------------------------------
        # Reset captured tensors
        # ----------------------------------------------------

        self.activations = None
        self.gradients = None

        # ----------------------------------------------------
        # Production preprocessing
        # ----------------------------------------------------

        rgb_image = image.convert(
            "RGB"
        )

        tensor = self.transform(
            rgb_image
        )

        tensor = tensor.unsqueeze(
            0
        ).to(
            self.device
        )

        # ----------------------------------------------------
        # Gradients are required for Grad-CAM
        # ----------------------------------------------------

        self.model.zero_grad(
            set_to_none=True
        )

        logits = self.model(
            tensor
        )

        probabilities = torch.softmax(
            logits,
            dim=1,
        )[0]

        target_score = logits[
            0,
            target_class,
        ]

        target_score.backward()

        # ----------------------------------------------------
        # Validate hook output
        # ----------------------------------------------------

        if self.activations is None:

            raise RuntimeError(
                "Grad-CAM activations were not captured."
            )

        if self.gradients is None:

            raise RuntimeError(
                "Grad-CAM gradients were not captured."
            )

        activations = (
            self.activations
        )

        gradients = (
            self.gradients
        )

        # ConvNeXt CNBlock output should be:
        # [batch, channels, height, width]

        if activations.ndim != 4:

            raise RuntimeError(
                "Unexpected ConvNeXt activation "
                f"shape: {tuple(activations.shape)}"
            )

        if gradients.shape != activations.shape:

            raise RuntimeError(
                "Grad-CAM gradient/activation "
                "shape mismatch."
            )

        # ----------------------------------------------------
        # Channel importance weights
        # ----------------------------------------------------

        weights = gradients.mean(
            dim=(2, 3),
            keepdim=True,
        )

        # ----------------------------------------------------
        # Weighted activation combination
        # ----------------------------------------------------

        cam = (
            weights
            * activations
        ).sum(
            dim=1,
            keepdim=True,
        )

        # Standard Grad-CAM keeps positive influence.
        cam = F.relu(
            cam
        )

        # ----------------------------------------------------
        # Upsample to original screenshot dimensions
        # ----------------------------------------------------

        original_width, original_height = (
            rgb_image.size
        )

        cam = F.interpolate(
            cam,
            size=(
                original_height,
                original_width,
            ),
            mode="bilinear",
            align_corners=False,
        )

        cam = cam[
            0,
            0,
        ]

        # ----------------------------------------------------
        # Normalise to 0..1
        # ----------------------------------------------------

        cam_min = float(
            cam.min().item()
        )

        cam_max = float(
            cam.max().item()
        )

        if (
            cam_max - cam_min
        ) > 1e-12:

            cam = (
                cam - cam_min
            ) / (
                cam_max - cam_min
            )

        else:

            cam = torch.zeros_like(
                cam
            )

        heatmap = (
            cam.detach()
            .cpu()
            .numpy()
            .astype(np.float32)
        )

        # ----------------------------------------------------
        # Compact explanation statistics
        # ----------------------------------------------------

        mean_attention = float(
            heatmap.mean()
        )

        max_attention = float(
            heatmap.max()
        )

        high_attention_ratio = float(
            np.mean(
                heatmap >= 0.70
            )
        )

        # Maximum-attention coordinate.
        max_index = np.unravel_index(
            np.argmax(heatmap),
            heatmap.shape,
        )

        max_y = int(
            max_index[0]
        )

        max_x = int(
            max_index[1]
        )

        # Normalised coordinates make evidence independent
        # of the original screenshot resolution.

        max_x_normalized = (
            max_x / original_width
            if original_width
            else 0.0
        )

        max_y_normalized = (
            max_y / original_height
            if original_height
            else 0.0
        )

        return {

            "target_class":
                target_class,

            "target_label":
                (
                    "Phishing"
                    if target_class == 1
                    else "Legitimate"
                ),

            "target_probability":
                round(
                    float(
                        probabilities[
                            target_class
                        ].item()
                    ),
                    6,
                ),

            "heatmap":
                heatmap,

            "heatmap_width":
                original_width,

            "heatmap_height":
                original_height,

            "mean_attention":
                round(
                    mean_attention,
                    6,
                ),

            "max_attention":
                round(
                    max_attention,
                    6,
                ),

            "high_attention_ratio":
                round(
                    high_attention_ratio,
                    6,
                ),

            "max_attention_point": {

                "x":
                    max_x,

                "y":
                    max_y,

                "x_normalized":
                    round(
                        max_x_normalized,
                        6,
                    ),

                "y_normalized":
                    round(
                        max_y_normalized,
                        6,
                    ),
            },

            "method":
                "Grad-CAM",

            "target_layer":
                "features[7][-1]",
        }


# ============================================================
# Singleton
# ============================================================

visual_explainability_service = (
    VisualExplainabilityService()
)