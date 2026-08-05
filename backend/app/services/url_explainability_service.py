"""
url_explainability_service.py

Native XGBoost TreeSHAP explainability service for
SecureSense AI URL Phishing Intelligence.

Uses XGBoost pred_contribs=True rather than the external
SHAP TreeExplainer to avoid runtime compatibility issues.
"""

from typing import Any, Dict, List

import pandas as pd
import xgboost as xgb

from app.services.url_model_service import url_model_service


class URLExplainabilityService:
    """
    Generates local feature contributions for the frozen
    XGBoost URL phishing model.
    """

    def __init__(self) -> None:

        pipeline = url_model_service.model

        # ----------------------------------------------------
        # Retrieve frozen pipeline components
        # ----------------------------------------------------

        self.imputer = pipeline.named_steps["imputer"]
        self.classifier = pipeline.named_steps["classifier"]

        self.feature_names = list(
            url_model_service.features
        )

        # ----------------------------------------------------
        # Retrieve native XGBoost booster
        # ----------------------------------------------------

        self.booster = self.classifier.get_booster()

        if len(self.feature_names) != 17:
            raise RuntimeError(
                "URL explainability requires exactly "
                "17 production features."
            )

    # ========================================================
    # Local explanation
    # ========================================================

    def explain(
        self,
        features: Dict[str, Any],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Generate the strongest local feature contributions.

        Positive contribution:
            pushes prediction toward phishing.

        Negative contribution:
            pushes prediction toward legitimate.
        """

        # ----------------------------------------------------
        # Build exact production feature frame
        # ----------------------------------------------------

        frame = pd.DataFrame(
            [
                [
                    features[name]
                    for name in self.feature_names
                ]
            ],
            columns=self.feature_names,
        )

        # ----------------------------------------------------
        # Apply the same imputation used during training
        # ----------------------------------------------------

        transformed = self.imputer.transform(
            frame
        )

        # ----------------------------------------------------
        # Native XGBoost input
        # ----------------------------------------------------

        dmatrix = xgb.DMatrix(
            transformed,
            feature_names=self.feature_names,
        )

        # ----------------------------------------------------
        # Native TreeSHAP contributions
        #
        # Output:
        #   17 feature contributions
        #   + 1 final bias/base value
        # ----------------------------------------------------

        contributions = self.booster.predict(
            dmatrix,
            pred_contribs=True,
        )[0]

        feature_contributions = contributions[:-1]

        # ----------------------------------------------------
        # Build explainable evidence
        # ----------------------------------------------------

        evidence: List[Dict[str, Any]] = []

        for index, feature_name in enumerate(
            self.feature_names
        ):

            contribution = float(
                feature_contributions[index]
            )

            value = float(
                transformed[0][index]
            )

            if contribution > 0:
                direction = "phishing"

            elif contribution < 0:
                direction = "legitimate"

            else:
                direction = "neutral"

            evidence.append(
                {
                    "feature": feature_name,
                    "value": value,
                    "shap_value": round(
                        contribution,
                        6,
                    ),
                    "direction": direction,
                    "strength": round(
                        abs(contribution),
                        6,
                    ),
                }
            )

        # ----------------------------------------------------
        # Strongest evidence first
        # ----------------------------------------------------

        evidence.sort(
            key=lambda item: item["strength"],
            reverse=True,
        )

        return evidence[:top_k]


# ============================================================
# Singleton
# ============================================================

url_explainability_service = (
    URLExplainabilityService()
)