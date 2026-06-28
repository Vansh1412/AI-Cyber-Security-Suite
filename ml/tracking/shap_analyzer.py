"""
ml/tracking/shap_analyzer.py
─────────────────────────────
SHAP Analyzer — Model explainability.

Generates global and local feature importance plots using SHAP,
compatible with TreeExplainers (XGBoost/RandomForest).

Usage
-----
    python -m ml.tracking.shap_analyzer
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
import shap
import yaml

from ml.models.base import load_feature_list
from src.config import MODEL_DIR, REPORT_DIR, TRAIN_PATH
from src.utils.logger import logger


def load_latest_xgboost() -> Any:
    """Load the best XGBoost model from disk."""
    import pickle
    
    # Optuna run saves as xgboost_optuna_best.pkl
    model_path = MODEL_DIR / "xgboost_optuna_best.pkl"
    if not model_path.exists():
        # Fallback to baseline
        model_path = MODEL_DIR / "xgboost_baseline.pkl"
        if not model_path.exists():
            raise FileNotFoundError("No trained XGBoost model found in ml/models/store/")
            
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return model


class ShapAnalyzer:
    def __init__(self, sample_size: int = 1000):
        self.sample_size = sample_size
        self.features = load_feature_list()
        
    def run(self):
        logger.info("=" * 55)
        logger.info("SHAP Analysis")
        logger.info("=" * 55)
        
        try:
            model = load_latest_xgboost()
            # XGBoostModel wraps the actual XGBClassifier in self.model
            xgb = model.model
            
            logger.info("Loaded model: %s", model.name)
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            return

        logger.info("Loading training sample (%d rows)...", self.sample_size)
        df = pd.read_parquet(TRAIN_PATH)
        feat_cols = [f for f in self.features if f in df.columns]
        
        # Take a random sample for SHAP to save time
        X_sample = df[feat_cols].sample(n=min(self.sample_size, len(df)), random_state=42)
        
        logger.info("Computing SHAP values (TreeExplainer)...")
        explainer = shap.TreeExplainer(xgb)
        
        # For multiclass, shap_values is a list of arrays (one per class)
        # or an array of shape (n_samples, n_features, n_classes) depending on SHAP version
        shap_values = explainer.shap_values(X_sample)
        
        # Ensure report dir exists
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        
        # Generate Summary Plot
        try:
            plt.figure(figsize=(10, 8))
            shap.summary_plot(shap_values, X_sample, plot_type="bar", class_names=model.classes_, show=False)
            plt.title("SHAP Feature Importance (Global)")
            plt.tight_layout()
            out_path = REPORT_DIR / "shap_summary_bar.png"
            plt.savefig(out_path, dpi=150)
            plt.close()
            logger.info("Saved SHAP summary bar plot -> %s", out_path)
            
            # If shap_values is a list (typical for XGBoost multiclass in older SHAP)
            if isinstance(shap_values, list):
                # We can generate a beeswarm for a specific class (e.g. phishing if it's index 1)
                # Just take the first class as an example, or all of them
                for i, class_name in enumerate(model.classes_):
                    plt.figure(figsize=(10, 8))
                    shap.summary_plot(shap_values[i], X_sample, show=False)
                    plt.title(f"SHAP Impact for class: {class_name}")
                    plt.tight_layout()
                    c_path = REPORT_DIR / f"shap_beeswarm_{class_name}.png"
                    plt.savefig(c_path, dpi=150)
                    plt.close()
                    logger.info("Saved SHAP beeswarm for %s -> %s", class_name, c_path)
        except Exception as e:
            logger.warning("Error generating SHAP plots: %s", e)

        logger.info("SHAP analysis complete.")

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    
    analyzer = ShapAnalyzer()
    analyzer.run()

if __name__ == "__main__":
    main()
