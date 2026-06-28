"""
backend/services/prediction.py
──────────────────────────────
Service for loading the model and making predictions using custom thresholds.
"""

import pickle
import yaml
import numpy as np
import pandas as pd
from typing import Tuple

from backend.core.config import settings
from src.utils.logger import logger


class PredictionService:
    def __init__(self):
        # 1. Load Model
        try:
            with open(settings.MODEL_PATH, "rb") as f:
                self.wrapper = pickle.load(f)
            self.model = self.wrapper.model
            self.classes = self.wrapper.classes_
            self.label_encoder = self.wrapper._label_encoder
            logger.info(f"PredictionService initialized. Loaded model: {self.wrapper.name}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise RuntimeError("Model loading failed.")

        # 2. Load custom thresholds
        try:
            with open(settings.CONFIG_PATH, "r") as f:
                cfg = yaml.safe_load(f)
                self.thresholds = cfg.get("thresholds", {})
            logger.info(f"Loaded threshold config: {self.thresholds}")
        except Exception as e:
            logger.warning(f"Failed to load thresholds, falling back to argmax: {e}")
            self.thresholds = {}

    def predict(self, df: pd.DataFrame) -> Tuple[str, float]:
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
            
            if conf >= threshold:
                if conf > max_malicious_conf:
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
