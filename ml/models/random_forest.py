"""
ml/models/random_forest.py
───────────────────────────
Random Forest — strong ensemble baseline.

Expected to beat Logistic Regression significantly. Provides
feature importance out of the box for comparison with SHAP.

Usage
-----
    python -m ml.models.random_forest
"""

from __future__ import annotations

import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ml.models.base import BaseModel, load_feature_list
from ml.tracking.mlflow_manager import ExperimentManager
from src.config import TRAIN_PATH, VAL_PATH
from src.utils.logger import logger


class RandomForestModel(BaseModel):
    """Random Forest with balanced class weights."""

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int | None = None,
        min_samples_leaf: int = 2,
    ) -> None:
        super().__init__(name="RandomForest")
        self.n_estimators     = n_estimators
        self.max_depth        = max_depth
        self.min_samples_leaf = min_samples_leaf

    def build(self):
        return RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            min_samples_leaf=self.min_samples_leaf,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        )


def train_and_log(
    dataset_scale: str = "100k",
    experiment_name: str = "phishing_detection",
) -> dict:
    logger.info("=" * 55)
    logger.info("Random Forest — Baseline")
    logger.info("=" * 55)

    features = load_feature_list()
    train_df = pd.read_parquet(TRAIN_PATH)
    val_df   = pd.read_parquet(VAL_PATH)

    feat_cols = [f for f in features if f in train_df.columns]
    X_train, y_train = train_df[feat_cols], train_df["label"]
    X_val,   y_val   = val_df[feat_cols],   val_df["label"]

    model   = RandomForestModel()
    manager = ExperimentManager(experiment_name)

    with manager.run("random_forest_baseline", dataset_scale=dataset_scale) as run:
        run.log_params({
            "model":             "RandomForest",
            "n_estimators":      model.n_estimators,
            "max_depth":         str(model.max_depth),
            "min_samples_leaf":  model.min_samples_leaf,
            "n_features":        len(feat_cols),
            "dataset_scale":     dataset_scale,
        })

        model.fit(X_train, y_train)

        train_metrics = model.evaluate(X_train, y_train)
        val_metrics   = model.evaluate(X_val,   y_val)

        run.log_metrics({f"train_{k}": v for k, v in train_metrics.items()})
        run.log_metrics({f"val_{k}":   v for k, v in val_metrics.items()})

        run.log_confusion_matrix(
            y_val, model.predict(X_val),
            class_names=sorted(y_val.unique()),
            title="Random Forest — Validation Confusion Matrix",
        )

        run.log_feature_importance(
            model=model.model,
            feature_names=feat_cols,
        )

        run.save_model(model.model, "random_forest_v1")

        logger.info("Val F1 (macro): %.4f | Accuracy: %.4f",
                    val_metrics["f1_macro"], val_metrics["accuracy"])

    return val_metrics


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    train_and_log()


if __name__ == "__main__":
    main()
