"""
ml/models/logistic.py
──────────────────────
Logistic Regression baseline — establishes the minimum performance bar.

If XGBoost doesn't beat this, something is wrong with the features or data.

Usage
-----
    python -m ml.models.logistic
"""

from __future__ import annotations

import sys

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline

from ml.models.base import BaseModel, load_feature_list
from ml.tracking.mlflow_manager import ExperimentManager
from src.config import TRAIN_PATH, VAL_PATH
from src.utils.logger import logger


class LogisticRegressionModel(BaseModel):
    """L2-regularised Logistic Regression with standard scaling."""

    def __init__(self, C: float = 1.0, max_iter: int = 1000) -> None:
        super().__init__(name="LogisticRegression")
        self.C        = C
        self.max_iter = max_iter

    def build(self):
        return Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    LogisticRegression(
                C=self.C,
                max_iter=self.max_iter,
                class_weight="balanced",
                solver="lbfgs",
                n_jobs=-1,
                random_state=42,
            )),
        ])


def train_and_log(
    dataset_scale: str = "100k",
    experiment_name: str = "phishing_detection",
) -> dict:
    """
    Full training run: load data → fit → evaluate → log to MLflow.

    Returns
    -------
    dict  val metrics
    """
    logger.info("=" * 55)
    logger.info("Logistic Regression — Baseline")
    logger.info("=" * 55)

    features = load_feature_list()
    train_df = pd.read_parquet(TRAIN_PATH)
    val_df   = pd.read_parquet(VAL_PATH)

    # Filter to selected features only
    feat_cols = [f for f in features if f in train_df.columns]
    X_train, y_train = train_df[feat_cols], train_df["label"]
    X_val,   y_val   = val_df[feat_cols],   val_df["label"]

    logger.info("Train: %s rows | Val: %s rows | Features: %d",
                f"{len(X_train):,}", f"{len(X_val):,}", len(feat_cols))

    model    = LogisticRegressionModel()
    manager  = ExperimentManager(experiment_name)

    with manager.run("logistic_regression_baseline", dataset_scale=dataset_scale) as run:
        run.log_params({
            "model":     "LogisticRegression",
            "C":         model.C,
            "max_iter":  model.max_iter,
            "n_features": len(feat_cols),
            "dataset_scale": dataset_scale,
        })

        model.fit(X_train, y_train)

        # Evaluate on both splits
        train_metrics = model.evaluate(X_train, y_train)
        val_metrics   = model.evaluate(X_val,   y_val)

        run.log_metrics({f"train_{k}": v for k, v in train_metrics.items()})
        run.log_metrics({f"val_{k}":   v for k, v in val_metrics.items()})

        run.log_confusion_matrix(
            y_val, model.predict(X_val),
            class_names=sorted(y_val.unique()),
            title="Logistic Regression — Validation Confusion Matrix",
        )

        run.save_model(model.model, "logistic_regression_v1")

        logger.info("Val F1 (macro): %.4f | Accuracy: %.4f",
                    val_metrics["f1_macro"], val_metrics["accuracy"])

    return val_metrics


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    train_and_log()


if __name__ == "__main__":
    main()
