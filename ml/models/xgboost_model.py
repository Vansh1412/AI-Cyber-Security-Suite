"""
ml/models/xgboost_model.py
───────────────────────────
XGBoost — the primary model for phishing detection.

Supports two modes:
  1. train_and_log()  — fixed hyperparameters (fast baseline)
  2. Use with ml/models/tuner.py — Optuna hyperparameter optimisation

Usage
-----
    # Quick baseline
    python -m ml.models.xgboost_model

    # After Optuna tuning
    from ml.models.xgboost_model import XGBoostModel
    model = XGBoostModel(**best_params)
    model.fit(X_train, y_train)
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from ml.models.base import BaseModel, compute_metrics, load_feature_list
from ml.tracking.mlflow_manager import ExperimentManager
from src.config import TRAIN_PATH, VAL_PATH
from src.utils.logger import logger


class XGBoostModel(BaseModel):
    """
    XGBoost multiclass classifier.

    Handles label encoding internally so callers always pass string labels.
    """

    def __init__(
        self,
        n_estimators:      int   = 300,
        max_depth:         int   = 6,
        learning_rate:     float = 0.1,
        subsample:         float = 0.8,
        colsample_bytree:  float = 0.8,
        min_child_weight:  int   = 1,
        gamma:             float = 0.0,
        reg_alpha:         float = 0.0,
        reg_lambda:        float = 1.0,
        use_label_encoder: bool  = False,
    ) -> None:
        super().__init__(name="XGBoost")
        self.params = dict(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            min_child_weight=min_child_weight,
            gamma=gamma,
            reg_alpha=reg_alpha,
            reg_lambda=reg_lambda,
            objective="multi:softprob",
            eval_metric="mlogloss",
            use_label_encoder=use_label_encoder,
            tree_method="hist",      # fast histogram method
            n_jobs=-1,
            random_state=42,
        )
        self._label_encoder = LabelEncoder()

    def build(self):
        return XGBClassifier(**self.params)

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "XGBoostModel":
        """Fit with label encoding."""
        if self.model is None:
            self.model = self.build()

        y_enc = self._label_encoder.fit_transform(y)
        self.params["num_class"] = len(self._label_encoder.classes_)
        self.model.set_params(num_class=self.params["num_class"])

        self.model.fit(X, y_enc)
        self._fitted = True
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Return original string labels."""
        self._check_fitted()
        encoded = self.model.predict(X)
        return self._label_encoder.inverse_transform(encoded)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.predict_proba(X)

    @property
    def classes_(self) -> list[str]:
        return list(self._label_encoder.classes_)


def train_and_log(
    dataset_scale: str = "100k",
    experiment_name: str = "phishing_detection",
    params: dict | None = None,
    run_name: str = "xgboost_baseline",
) -> dict:
    """
    Train XGBoost and log everything to MLflow.

    Parameters
    ----------
    params : dict | None
        Override default XGBoost hyperparameters (e.g., from Optuna best trial).
    """
    logger.info("=" * 55)
    logger.info("XGBoost — %s", run_name)
    logger.info("=" * 55)

    features = load_feature_list()
    train_df = pd.read_parquet(TRAIN_PATH)
    val_df   = pd.read_parquet(VAL_PATH)

    feat_cols = [f for f in features if f in train_df.columns]
    X_train, y_train = train_df[feat_cols], train_df["label"]
    X_val,   y_val   = val_df[feat_cols],   val_df["label"]

    model_kwargs = params or {}
    model   = XGBoostModel(**model_kwargs)
    manager = ExperimentManager(experiment_name)

    with manager.run(run_name, dataset_scale=dataset_scale) as run:
        run.log_params({
            "model":         "XGBoost",
            "n_features":    len(feat_cols),
            "dataset_scale": dataset_scale,
            **model.params,
        })

        model.fit(X_train, y_train)

        train_metrics = model.evaluate(X_train, y_train)
        val_metrics   = model.evaluate(X_val,   y_val)

        run.log_metrics({f"train_{k}": v for k, v in train_metrics.items()})
        run.log_metrics({f"val_{k}":   v for k, v in val_metrics.items()})

        run.log_confusion_matrix(
            y_val, model.predict(X_val),
            class_names=model.classes_,
            title=f"XGBoost — {run_name}",
        )

        run.log_feature_importance(
            model=model.model,
            feature_names=feat_cols,
        )

        run.save_model(model, run_name.replace(" ", "_"), flavor="xgboost")

        logger.info("Val F1 (macro): %.4f | Accuracy: %.4f | MCC: %.4f",
                    val_metrics.get("f1_macro", 0),
                    val_metrics.get("accuracy", 0),
                    val_metrics.get("mcc", 0))

    return val_metrics


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    train_and_log()


if __name__ == "__main__":
    main()
