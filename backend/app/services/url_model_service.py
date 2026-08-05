"""
url_model_service.py

Inference service for the frozen SecureSense AI
17-feature URL phishing detection model.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd

from app.services.url_feature_service import url_feature_service


class URLModelService:
    """
    Runs the production URL phishing model.
    """

    def __init__(self) -> None:

        # ====================================================
        # Paths
        # ====================================================

        app_dir = Path(__file__).resolve().parents[1]

        self.model_path = (
            app_dir
            / "ai"
            / "url"
            / "url_phishing_model_17f.joblib"
        )

        self.contract_path = (
            app_dir
            / "ai"
            / "url"
            / "feature_contract.json"
        )

        # ====================================================
        # Validate artefacts
        # ====================================================

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"URL model not found: {self.model_path}"
            )

        if not self.contract_path.exists():
            raise FileNotFoundError(
                f"Feature contract not found: {self.contract_path}"
            )

        # ====================================================
        # Load model
        # ====================================================

        self.model = joblib.load(
            self.model_path
        )

        # ====================================================
        # Load feature contract
        # ====================================================

        with open(
            self.contract_path,
            "r",
            encoding="utf-8",
        ) as file:
            self.contract = json.load(file)

        self.features = self.contract["features"]

        # ====================================================
        # Contract validation
        # ====================================================

        if len(self.features) != 17:
            raise RuntimeError(
                "URL model must use exactly 17 features."
            )

        if hasattr(
            self.model,
            "feature_names_in_",
        ):
            trained_features = list(
                self.model.feature_names_in_
            )

            if trained_features != self.features:
                raise RuntimeError(
                    "URL model feature order does not "
                    "match feature_contract.json."
                )

    # ========================================================
    # Prediction
    # ========================================================

    def predict(
        self,
        url: str,
        include_features: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyse a URL using the frozen 17-feature
        XGBoost phishing model.

        include_features=True keeps the feature vector
        available for SHAP/EEL explainability.
        """

        start = time.perf_counter()

        # ====================================================
        # Feature extraction
        # ====================================================

        features = url_feature_service.extract(
            url
        )

        frame = pd.DataFrame(
            [
                [
                    features[feature]
                    for feature in self.features
                ]
            ],
            columns=self.features,
        )

        # ====================================================
        # ML inference
        # ====================================================

        probabilities = self.model.predict_proba(
            frame
        )[0]

        legitimate_probability = float(
            probabilities[0]
        )

        phishing_probability = float(
            probabilities[1]
        )

        predicted_class = int(
            phishing_probability >= 0.5
        )

        label = (
            "Phishing"
            if predicted_class == 1
            else "Legitimate"
        )

        confidence = max(
            legitimate_probability,
            phishing_probability,
        )

        inference_time_ms = (
            time.perf_counter() - start
        ) * 1000

        # ====================================================
        # Result
        # ====================================================

        result: Dict[str, Any] = {
            "label": label,

            "class_id": predicted_class,

            "confidence": round(
                confidence,
                6,
            ),

            "confidence_percent": round(
                confidence * 100,
                4,
            ),

            "phishing_probability": round(
                phishing_probability,
                6,
            ),

            "phishing_probability_percent": round(
                phishing_probability * 100,
                4,
            ),

            "legitimate_probability": round(
                legitimate_probability,
                6,
            ),

            "legitimate_probability_percent": round(
                legitimate_probability * 100,
                4,
            ),

            "risk_score": round(
                phishing_probability * 100,
                2,
            ),

            "inference_time_ms": round(
                inference_time_ms,
                2,
            ),

            # Useful later when writing the prediction
            # and its explanation into EEL.
            "model_info": {
                "module": "URL Intelligence",
                "model_type": "XGBoost",
                "feature_count": 17,
                "model_file": self.model_path.name,
            },
        }

        if include_features:
            result["features"] = features

        return result


# ============================================================
# Singleton
# ============================================================

url_model_service = URLModelService()