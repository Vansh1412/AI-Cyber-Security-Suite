"""
ml/models/base.py
──────────────────
BaseModel — abstract base class for all models in this project.

Every model (Logistic Regression, Random Forest, XGBoost, etc.)
inherits from this class and gets:
  - Standardised fit/predict/evaluate interface
  - Automatic metric computation (accuracy, F1, ROC-AUC, MCC)
  - Training configuration loading from training.yaml
  - Integration point for ExperimentManager

Usage
-----
    class MyModel(BaseModel):
        def build(self): ...
        def fit(self, X, y): ...
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml

from src.config import SELECTED_FEATURES, TRAINING_CONFIG
from src.utils.logger import logger


def load_training_config() -> dict:
    with open(TRAINING_CONFIG, "r") as f:
        return yaml.safe_load(f)


def load_feature_list() -> list[str]:
    """Load the selected feature list from selected_features.json."""
    if not SELECTED_FEATURES.exists():
        raise FileNotFoundError(
            f"selected_features.json not found at {SELECTED_FEATURES}. "
            "Run: python -m ml.selection.selector"
        )
    data = json.loads(SELECTED_FEATURES.read_text())
    return data["features"]


def compute_metrics(y_true, y_pred, y_proba=None) -> dict[str, float]:
    """
    Compute a full suite of classification metrics.

    Handles both binary and multiclass targets automatically.

    Returns
    -------
    dict with keys: accuracy, f1_macro, f1_weighted, precision_macro,
    recall_macro, mcc, roc_auc (if y_proba provided).
    """
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        matthews_corrcoef,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    metrics: dict[str, float] = {
        "accuracy":          round(float(accuracy_score(y_true, y_pred)),              6),
        "f1_macro":          round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)),     6),
        "f1_weighted":       round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),  6),
        "precision_macro":   round(float(precision_score(y_true, y_pred, average="macro", zero_division=0)),   6),
        "recall_macro":      round(float(recall_score(y_true, y_pred, average="macro", zero_division=0)),      6),
        "mcc":               round(float(matthews_corrcoef(y_true, y_pred)),            6),
    }

    # Per-class metrics
    try:
        from sklearn.metrics import classification_report
        # Extract per-class f1/precision/recall from classification report dict
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        for cls_name, cls_metrics in report.items():
            if isinstance(cls_metrics, dict) and cls_name not in ("accuracy", "macro avg", "weighted avg"):
                metrics[f"{cls_name}_precision"] = round(cls_metrics["precision"], 4)
                metrics[f"{cls_name}_recall"] = round(cls_metrics["recall"], 4)
                metrics[f"{cls_name}_f1"] = round(cls_metrics["f1-score"], 4)
    except Exception as e:
        logger.warning(f"Could not compute per-class metrics: {e}")

    if y_proba is not None:
        try:
            n_classes = len(np.unique(y_true))
            multi_class = "ovr" if n_classes > 2 else "raise"
            metrics["roc_auc"] = round(float(
                roc_auc_score(y_true, y_proba, multi_class=multi_class, average="macro")
            ), 6)
        except Exception:
            pass  # ROC-AUC not always computable (e.g. missing classes in small val)

    return metrics


class BaseModel(ABC):
    """
    Abstract base for all phishing detection models.

    Subclasses must implement: `build()` and optionally override `fit()`.

    Parameters
    ----------
    name : str
        Human-readable model name (used in logs and MLflow).
    """

    def __init__(self, name: str) -> None:
        self.name    = name
        self.config  = load_training_config()
        self.model   = None
        self._fitted = False

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def build(self) -> Any:
        """Instantiate and return the underlying sklearn/XGBoost model."""
        ...

    # ── Concrete methods ───────────────────────────────────────────────────────

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "BaseModel":
        """Fit the model. Subclasses may override for custom logic."""
        if self.model is None:
            self.model = self.build()
        t0 = time.perf_counter()
        logger.info("Training %s on %s rows × %s features…", self.name, f"{len(X):,}", X.shape[1])
        self.model.fit(X, y)
        self._fitted = True
        logger.info("%s trained in %.1fs", self.name, time.perf_counter() - t0)
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        self._check_fitted()
        return self.model.predict(X)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray | None:
        self._check_fitted()
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        return None

    def evaluate(self, X: pd.DataFrame, y: pd.Series) -> dict[str, float]:
        """Compute all metrics on a dataset split."""
        y_pred  = self.predict(X)
        y_proba = self.predict_proba(X)
        metrics = compute_metrics(y, y_pred, y_proba)
        return metrics

    def _check_fitted(self) -> None:
        if not self._fitted or self.model is None:
            raise RuntimeError(f"{self.name}: call fit() before predict().")
