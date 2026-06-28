"""
ml/models/thresholds.py
────────────────────────
Threshold Optimization

Finds optimal decision thresholds on the validation set for each class
to maximize precision/recall balance.

Usage
-----
    python -m ml.models.thresholds
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import classification_report, f1_score

from ml.models.base import load_feature_list
from src.config import CONFIGS_DIR, MODEL_DIR, VAL_PATH
from src.utils.logger import logger


def optimize_thresholds(y_true: np.ndarray, y_proba: np.ndarray, classes: list[str]) -> dict:
    """Find the best threshold for each class vs the rest."""
    best_thresholds = {}
    
    for i, cls in enumerate(classes):
        best_f1 = 0
        best_t = 0.5
        
        # We only really care about optimizing thresholds for minority classes (phishing, defacement, malware)
        # Legitimate can just be the default fallback.
        if cls == "legitimate":
            best_thresholds[cls] = 0.5
            continue

        y_true_binary = (y_true == i).astype(int)
        y_proba_cls = y_proba[:, i]
        
        # Search thresholds between 0.1 and 0.9
        for t in np.arange(0.1, 0.95, 0.05):
            y_pred_binary = (y_proba_cls >= t).astype(int)
            f1 = f1_score(y_true_binary, y_pred_binary, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = round(float(t), 2)
                
        best_thresholds[cls] = best_t
        logger.info("Optimized %s threshold: %.2f (F1 vs rest: %.4f)", cls, best_t, best_f1)
        
    return best_thresholds


def main():
    logger.info("=" * 55)
    logger.info("Threshold Optimization")
    logger.info("=" * 55)

    model_path = MODEL_DIR / "xgboost_calibrated.pkl"
    if not model_path.exists():
        model_path = MODEL_DIR / "xgboost_optuna_best.pkl"
        
    with open(model_path, "rb") as f:
        wrapper = pickle.load(f)

    features = load_feature_list()
    val_df = pd.read_parquet(VAL_PATH)
    
    feat_cols = [f for f in features if f in val_df.columns]
    X_val = val_df[feat_cols]
    
    y_val_str = val_df["label"]
    y_val = wrapper._label_encoder.transform(y_val_str)
    classes = wrapper.classes_

    logger.info("Generating predictions...")
    if hasattr(wrapper.model, "predict_proba"):
        y_proba = wrapper.model.predict_proba(X_val)
    else:
        logger.error("Model does not support predict_proba")
        return

    # Baseline argmax predictions
    y_pred_base = np.argmax(y_proba, axis=1)
    logger.info("Baseline classification report (argmax):")
    print(classification_report(y_val, y_pred_base, target_names=classes))

    # Optimize
    thresholds = optimize_thresholds(y_val, y_proba, classes)

    # Save to model config
    config_path = CONFIGS_DIR / "model_config.yaml"
    
    # Load existing if present
    if config_path.exists():
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
        
    cfg["thresholds"] = thresholds
    
    with open(config_path, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)
        
    logger.info("Saved optimal thresholds to %s", config_path.name)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
