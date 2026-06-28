"""
ml/models/calibrate.py
───────────────────────
Probability Calibration & ONNX Export

1. Loads the best XGBoost model.
2. Calibrates probabilities using Isotonic Regression on the validation set.
3. Exports the final calibrated model to ONNX.

Usage
-----
    python -m ml.models.calibrate
"""

from __future__ import annotations

import pickle
import sys
from pathlib import Path

import onnxmltools
import pandas as pd
from onnxmltools.convert.common.data_types import FloatTensorType
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType as SklearnFloatTensorType
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import log_loss

from ml.models.base import load_feature_list
from src.config import MODEL_DIR, VAL_PATH
from src.utils.logger import logger


def main():
    logger.info("=" * 55)
    logger.info("Probability Calibration & ONNX Export")
    logger.info("=" * 55)

    # 1. Load the uncalibrated best model (XGBoostModel wrapper)
    model_path = MODEL_DIR / "xgboost_optuna_best.pkl"
    if not model_path.exists():
        logger.error(f"Best model not found at {model_path}. Run tuner first.")
        sys.exit(1)

    with open(model_path, "rb") as f:
        wrapper = pickle.load(f)

    # We want to calibrate the raw sklearn-compatible XGBClassifier
    base_xgb = wrapper.model

    # 2. Load validation data to fit the calibrator
    features = load_feature_list()
    val_df = pd.read_parquet(VAL_PATH)
    
    feat_cols = [f for f in features if f in val_df.columns]
    X_val = val_df[feat_cols]
    
    # We must encode the labels just like the wrapper did
    y_val_str = val_df["label"]
    y_val = wrapper._label_encoder.transform(y_val_str)

    # Measure uncalibrated loss
    uncalibrated_probs = base_xgb.predict_proba(X_val)
    uncalibrated_loss = log_loss(y_val, uncalibrated_probs)
    logger.info("Uncalibrated Log Loss: %.4f", uncalibrated_loss)

    # 3. Fit CalibratedClassifierCV
    logger.info("Calibrating probabilities using Isotonic Regression (cv=3)...")
    calibrator = CalibratedClassifierCV(estimator=base_xgb, method="isotonic", cv=3)
    calibrator.fit(X_val, y_val)

    calibrated_probs = calibrator.predict_proba(X_val)
    calibrated_loss = log_loss(y_val, calibrated_probs)
    logger.info("Calibrated Log Loss:   %.4f", calibrated_loss)

    # Replace the wrapper's internal model with the calibrated one
    wrapper.model = calibrator
    wrapper.name = "XGBoost_Calibrated"

    calibrated_path = MODEL_DIR / "xgboost_calibrated.pkl"
    with open(calibrated_path, "wb") as f:
        pickle.dump(wrapper, f)
    logger.info("Saved calibrated wrapper -> %s", calibrated_path.name)

    # 4. Export to ONNX
    logger.info("Converting calibrated model to ONNX...")
    try:
        # Since calibrator is a scikit-learn object, we use skl2onnx
        # But it contains an xgboost model inside, so we must register the xgboost converter.
        from onnxmltools.convert import convert_xgboost
        from skl2onnx import update_registered_converter
        from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
        from xgboost import XGBClassifier
        from onnxmltools.convert.xgboost.operator_converters.XGBoost import convert_xgboost as convert_xgb_node
        
        update_registered_converter(
            XGBClassifier, 
            'XGBoostXGBClassifier',
            calculate_linear_classifier_output_shapes, 
            convert_xgb_node
        )
        
        initial_type = [('float_input', SklearnFloatTensorType([None, len(feat_cols)]))]
        onx = convert_sklearn(
            calibrator, 
            initial_types=initial_type,
            target_opset=12,
            options={id(calibrator): {'zipmap': False}}  # Disable zipmap for speed + standard tensor output
        )
        
        onnx_path = MODEL_DIR / "xgboost_calibrated.onnx"
        with open(onnx_path, "wb") as f:
            f.write(onx.SerializeToString())
            
        logger.info("Saved ONNX model -> %s", onnx_path.name)
    except Exception as e:
        logger.error("ONNX conversion failed: %s", e)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
