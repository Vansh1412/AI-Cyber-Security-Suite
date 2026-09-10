"""
backend/services/explainer.py
──────────────────────────────
Service for generating real-time SHAP feature attributions.
"""

import pickle

import pandas as pd
import shap

from backend.services.model_lifecycle import (
    compute_file_sha256,
    get_registry,
    validate_model_path,
)
from src.config import MODEL_DIR
from src.utils.logger import logger


class ExplainerService:
    def __init__(self):
        self.reload_model()

    def reload_model(self) -> None:
        """
        Dynamically reload TreeExplainer against the active champion model.
        Falls back to baseline uncalibrated model if active champion is unexplainable.
        Propagates reload failure so coordinated lifecycle manager can trigger rollback.
        """
        try:
            from backend.core.config import settings
            model_file = settings.MODEL_PATH.name
            verified_path = validate_model_path(model_file)
            if not verified_path.exists():
                verified_path = MODEL_DIR / "xgboost_optuna_best.pkl"

            # Verify checksum before unpickling (Finding 4)
            registry = get_registry()
            recorded_sha = registry.get("artifacts_sha256", {}).get(model_file)
            if recorded_sha:
                computed_sha = compute_file_sha256(verified_path)
                if computed_sha != recorded_sha:
                    raise ValueError(
                        f"Integrity check failed for {model_file} in ExplainerService: expected {recorded_sha}, got {computed_sha}"
                    )

            with open(verified_path, "rb") as f:
                new_wrapper = pickle.load(f)

            # Handle CalibratedClassifierCV vs direct XGBClassifier
            underlying_model = new_wrapper.model
            if hasattr(underlying_model, "calibrated_classifiers_"):
                # Extract first base estimator from calibrated ensemble
                underlying_model = underlying_model.calibrated_classifiers_[0].estimator

            new_explainer = shap.TreeExplainer(underlying_model)
            self.wrapper = new_wrapper
            self.model = underlying_model
            self.explainer = new_explainer
            logger.info("ExplainerService reloaded against model: %s", verified_path.name)
        except Exception as e:
            logger.error("Failed to reload ExplainerService: %s", e)
            if not hasattr(self, "explainer"):
                # Initial fallback
                try:
                    fallback_path = MODEL_DIR / "xgboost_optuna_best.pkl"
                    with open(fallback_path, "rb") as f:
                        self.wrapper = pickle.load(f)
                    self.model = self.wrapper.model
                    self.explainer = shap.TreeExplainer(self.model)
                    logger.info("ExplainerService initialized with fallback model: %s", fallback_path.name)
                except Exception as fb_err:
                    raise RuntimeError(f"Explainer fallback failed: {fb_err}") from e
            else:
                # Running service failed to reload: raise so coordinator can revert PredictionService
                raise RuntimeError(f"Explainer reload failed against new champion: {e}") from e

    def explain(self, df: pd.DataFrame, predicted_class: str) -> list[dict]:
        """
        Returns the top 5 features that pushed the prediction towards the predicted class.
        """
        # 1. Get SHAP values
        shap_values = self.explainer.shap_values(df)
        
        # 2. Get class index
        class_idx = self.wrapper._label_encoder.transform([predicted_class])[0]
        
        # For multi-class, shap_values is a list of arrays (one per class).
        # We extract the SHAP values for the predicted class.
        class_shap_values = shap_values[class_idx][0]  # First row
        
        # 3. Pair features with their SHAP impacts
        features = df.columns.tolist()
        impacts = []
        for i, feat in enumerate(features):
            impact_val = class_shap_values[i]
            # We only care about positive impacts pushing toward THIS class
            if impact_val > 0:
                impacts.append({
                    "feature": feat,
                    "value": float(df.iloc[0][feat]),
                    "impact": float(impact_val)
                })
                
        # 4. Sort by highest impact and take top 5
        impacts.sort(key=lambda x: x["impact"], reverse=True)
        top_impacts = impacts[:5]
        
        return top_impacts
