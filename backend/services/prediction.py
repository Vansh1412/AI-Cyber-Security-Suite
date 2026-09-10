"""
backend/services/prediction.py
──────────────────────────────
Service for loading the model and making predictions using custom thresholds.
"""

import json
import pickle

import numpy as np
import pandas as pd
import yaml

from backend.core.config import settings
from backend.services.model_lifecycle import (
    compute_file_sha256,
    get_registry,
    validate_model_path,
)
from src.utils.logger import logger


class PredictionService:
    def __init__(self):
        with open(settings.SCHEMA_PATH) as f:
            self.schema: list[str] = json.load(f)["features"]
        self.reload_model()

    def reload_model(self) -> None:
        """
        Reload model weights from registry path and re-read cascade thresholds.
        Loads into local variables first, validates path, checks artifact SHA-256,
        and runs a smoke-test prediction before atomically swapping references.
        If loading fails, preserves the existing champion without corrupting state.
        """
        # 1. Load Model into local variable with path & integrity validation
        try:
            model_file = settings.MODEL_PATH.name
            verified_path = validate_model_path(model_file)
            if not verified_path.exists():
                raise FileNotFoundError(f"Model file '{model_file}' does not exist at {verified_path}")

            # Verify checksum if present in registry
            registry = get_registry()
            recorded_sha = registry.get("artifacts_sha256", {}).get(model_file)
            if recorded_sha:
                computed_sha = compute_file_sha256(verified_path)
                if computed_sha != recorded_sha:
                    raise ValueError(
                        f"Integrity check failed for {model_file}: expected {recorded_sha}, got {computed_sha}"
                    )

            with open(verified_path, "rb") as f:
                new_wrapper = pickle.load(f)

            if not hasattr(new_wrapper, "model") or not hasattr(new_wrapper, "classes_"):
                raise TypeError(f"Loaded object from {model_file} is not a valid model wrapper.")

            new_model = new_wrapper.model
            new_classes = new_wrapper.classes_
            new_label_encoder = getattr(new_wrapper, "_label_encoder", None)

            # Smoke-test inference before pointer assignment
            smoke_df = pd.DataFrame([[0.0] * len(self.schema)], columns=self.schema)
            _ = new_model.predict_proba(smoke_df)

            logger.info("PredictionService: Loaded & smoke-tested model '%s' from %s", new_wrapper.name, model_file)
        except Exception as e:
            logger.error("Failed to safely load model from %s: %s", settings.MODEL_PATH, e)
            if not hasattr(self, "model") or self.model is None:
                raise RuntimeError("Initial model loading failed.") from e
            logger.warning("Retaining existing model in memory due to load failure.")
            return

        # 2. Load custom thresholds
        try:
            with open(settings.CONFIG_PATH) as f:
                cfg = yaml.safe_load(f)
                new_thresholds = cfg.get("thresholds", {})
            logger.info("Loaded threshold config: %s", new_thresholds)
        except Exception as e:
            logger.warning("Failed to load thresholds, falling back to existing/empty: %s", e)
            new_thresholds = getattr(self, "thresholds", {})

        # 3. Atomic reference swap
        self.wrapper = new_wrapper
        self.model = new_model
        self.classes = new_classes
        self.label_encoder = new_label_encoder
        self.thresholds = new_thresholds


    def predict(self, df: pd.DataFrame) -> tuple[str, float]:
        """
        Predict class and confidence for a single row DataFrame.
        Applies cascade thresholding if configured.
        """
        # Get probabilities for all classes
        probas = self.model.predict_proba(df)[0]
        
        # Cascade Logic: 
        # Check malicious classes first using their specific thresholds.
        # If none trigger, fallback to legitimate.
        malicious_order = ["malware", "phishing", "defacement"]
        
        predicted_class = None
        max_malicious_conf = 0.0
        
        for cls_name in malicious_order:
            if cls_name not in self.classes:
                continue
                
            idx = self.label_encoder.transform([cls_name])[0]
            conf = probas[idx]
            threshold = self.thresholds.get(cls_name, 0.5)
            
            if conf >= threshold and conf > max_malicious_conf:
                max_malicious_conf = conf
                predicted_class = cls_name
                    
        # If a malicious class crossed its threshold, return it
        if predicted_class:
            return predicted_class, float(max_malicious_conf)
            
        # Fallback to standard argmax if no threshold crossed
        best_idx = np.argmax(probas)
        predicted_class = self.label_encoder.inverse_transform([best_idx])[0]
        confidence = probas[best_idx]
        
        return predicted_class, float(confidence)
