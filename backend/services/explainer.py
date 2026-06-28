"""
backend/services/explainer.py
──────────────────────────────
Service for generating real-time SHAP feature attributions.
"""

import pickle
import pandas as pd
import shap
from typing import List, Dict

from src.config import MODEL_DIR
from src.utils.logger import logger


class ExplainerService:
    def __init__(self):
        try:
            # We load the uncalibrated model for SHAP, because TreeExplainer
            # needs the raw XGBoost Booster, not the CalibratedClassifierCV wrapper.
            uncalibrated_path = MODEL_DIR / "xgboost_optuna_best.pkl"
            with open(uncalibrated_path, "rb") as f:
                self.wrapper = pickle.load(f)
                
            self.model = self.wrapper.model
            self.explainer = shap.TreeExplainer(self.model)
            
            logger.info("ExplainerService initialized with TreeExplainer.")
        except Exception as e:
            logger.error(f"Failed to initialize ExplainerService: {e}")
            raise RuntimeError("Explainer loading failed.")

    def explain(self, df: pd.DataFrame, predicted_class: str) -> List[Dict]:
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
