"""
nlp_explainability_service.py

SecureSense AI DistilBERT explainability service.

Generates token-level attribution evidence for the frozen
NLP security classifier without modifying model weights.

Method:
    Integrated Gradients over DistilBERT input embeddings.
"""

from __future__ import annotations

from typing import Any, Dict, List

import torch
import torch.nn.functional as F

from app.ai.nlp.inference import (
    get_device,
    get_model,
    get_tokenizer,
)
from app.ai.nlp.labels import ID_TO_LABEL
from app.ai.nlp.predictor import MAX_LENGTH


# ============================================================
# Configuration
# ============================================================

DEFAULT_STEPS = 32
DEFAULT_TOP_K = 10


# ============================================================
# Service
# ============================================================

class NLPExplainabilityService:
    """
    Generates token-level Integrated Gradients explanations
    using the same frozen DistilBERT singleton used for normal
    production inference.
    """

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------

    @staticmethod
    def _clean_text(text: str) -> str:

        if not isinstance(text, str):
            raise TypeError(
                "Input text must be a string."
            )

        text = " ".join(
            text.strip().split()
        )

        if not text:
            raise ValueError(
                "Input text cannot be empty."
            )

        return text

    # --------------------------------------------------------
    # Explain
    # --------------------------------------------------------

    def explain(
        self,
        text: str,
        target_class: int | None = None,
        steps: int = DEFAULT_STEPS,
        top_k: int = DEFAULT_TOP_K,
    ) -> Dict[str, Any]:

        if steps < 2:
            raise ValueError(
                "Integrated Gradients steps must be >= 2."
            )

        if top_k < 1:
            raise ValueError(
                "top_k must be >= 1."
            )

        text = self._clean_text(
            text
        )

        model = get_model()
        tokenizer = get_tokenizer()
        device = get_device()

        model.eval()

        # ----------------------------------------------------
        # 1. Tokenize exactly like production inference
        # ----------------------------------------------------

        encoded = tokenizer(
            text,
            max_length=MAX_LENGTH,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )

        input_ids = encoded[
            "input_ids"
        ].to(device)

        attention_mask = encoded[
            "attention_mask"
        ].to(device)

        # ----------------------------------------------------
        # 2. Reproduce frozen prediction
        # ----------------------------------------------------

        with torch.inference_mode():

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )

            probabilities = F.softmax(
                outputs.logits,
                dim=-1,
            ).squeeze(0)

        predicted_class = int(
            torch.argmax(
                probabilities
            ).item()
        )

        if predicted_class not in ID_TO_LABEL:

            raise RuntimeError(
                "Model produced an unknown class ID: "
                f"{predicted_class}"
            )

        if target_class is None:

            target_class = (
                predicted_class
            )

        if target_class not in ID_TO_LABEL:

            raise ValueError(
                "Unknown target class ID: "
                f"{target_class}"
            )

        target_probability = float(
            probabilities[
                target_class
            ].item()
        )

        # ----------------------------------------------------
        # 3. Obtain frozen input embeddings
        # ----------------------------------------------------

        embedding_layer = (
            model.get_input_embeddings()
        )

        with torch.no_grad():

            input_embeddings = (
                embedding_layer(
                    input_ids
                )
            )

        # ----------------------------------------------------
        # 4. Baseline
        #
        # Zero embedding is used as the attribution baseline.
        # ----------------------------------------------------

        baseline_embeddings = (
            torch.zeros_like(
                input_embeddings
            )
        )

        embedding_delta = (
            input_embeddings
            - baseline_embeddings
        )

        # ----------------------------------------------------
        # 5. Integrated Gradients
        # ----------------------------------------------------

        accumulated_gradients = (
            torch.zeros_like(
                input_embeddings
            )
        )

        alphas = torch.linspace(
            0.0,
            1.0,
            steps=steps,
            device=device,
        )

        for alpha in alphas:

            interpolated = (
                baseline_embeddings
                + alpha * embedding_delta
            )

            interpolated = (
                interpolated.detach()
            )

            interpolated.requires_grad_(
                True
            )

            outputs = model(
                inputs_embeds=interpolated,
                attention_mask=attention_mask,
            )

            target_logit = (
                outputs.logits[
                    0,
                    target_class,
                ]
            )

            gradient = torch.autograd.grad(
                outputs=target_logit,
                inputs=interpolated,
                retain_graph=False,
                create_graph=False,
            )[0]

            accumulated_gradients += (
                gradient.detach()
            )

        average_gradients = (
            accumulated_gradients
            / float(steps)
        )

        integrated_gradients = (
            embedding_delta
            * average_gradients
        )

        # ----------------------------------------------------
        # 6. Collapse embedding dimension
        #
        # Signed attribution:
        #   positive -> supports target class
        #   negative -> opposes target class
        # ----------------------------------------------------

        token_attributions = (
            integrated_gradients
            .sum(dim=-1)
            .squeeze(0)
        )

        # ----------------------------------------------------
        # 7. Extract real tokens
        # ----------------------------------------------------

        tokens = tokenizer.convert_ids_to_tokens(
            input_ids[
                0
            ].detach().cpu().tolist()
        )

        mask_values = (
            attention_mask[
                0
            ].detach().cpu().tolist()
        )

        special_ids = set(
            tokenizer.all_special_ids
        )

        token_records: List[
            Dict[str, Any]
        ] = []

        for index, (
            token,
            token_id,
            mask_value,
        ) in enumerate(
            zip(
                tokens,
                input_ids[
                    0
                ].detach().cpu().tolist(),
                mask_values,
            )
        ):

            if mask_value == 0:
                continue

            if token_id in special_ids:
                continue

            attribution = float(
                token_attributions[
                    index
                ].detach().cpu().item()
            )

            token_records.append(
                {
                    "token": token,
                    "token_index": index,
                    "attribution": attribution,
                    "strength": abs(
                        attribution
                    ),
                    "direction": (
                        "supports_target"
                        if attribution >= 0
                        else "opposes_target"
                    ),
                }
            )

        # ----------------------------------------------------
        # 8. Rank by absolute attribution
        # ----------------------------------------------------

        token_records.sort(
            key=lambda item: item[
                "strength"
            ],
            reverse=True,
        )

        top_tokens = (
            token_records[
                :top_k
            ]
        )

        # ----------------------------------------------------
        # 9. Normalised importance
        # ----------------------------------------------------

        total_strength = sum(
            item["strength"]
            for item in token_records
        )

        for item in top_tokens:

            if total_strength > 0:

                item[
                    "normalized_strength"
                ] = (
                    item["strength"]
                    / total_strength
                )

            else:

                item[
                    "normalized_strength"
                ] = 0.0

        # ----------------------------------------------------
        # 10. Class probabilities
        # ----------------------------------------------------

        probability_dict = {

            ID_TO_LABEL[class_id]:
                round(
                    float(
                        probabilities[
                            class_id
                        ].item()
                    ),
                    6,
                )

            for class_id
            in sorted(
                ID_TO_LABEL
            )
        }

        # ----------------------------------------------------
        # 11. Result
        # ----------------------------------------------------

        return {

            "method":
                "Integrated Gradients",

            "predicted_class":
                predicted_class,

            "predicted_label":
                ID_TO_LABEL[
                    predicted_class
                ],

            "target_class":
                target_class,

            "target_label":
                ID_TO_LABEL[
                    target_class
                ],

            "target_probability":
                round(
                    target_probability,
                    6,
                ),

            "probabilities":
                probability_dict,

            "steps":
                steps,

            "top_tokens":
                top_tokens,

            "token_count":
                len(
                    token_records
                ),
        }


# ============================================================
# Singleton
# ============================================================

nlp_explainability_service = (
    NLPExplainabilityService()
)