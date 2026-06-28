"""
ml/tracking/mlflow_manager.py
──────────────────────────────
ExperimentManager — the single interface for all experiment tracking.

Every model in this project (Logistic Regression, Random Forest,
XGBoost, LightGBM, etc.) uses this identical interface:

    manager = ExperimentManager("xgboost_baseline")

    with manager.run("run_01") as run:
        run.log_params({"n_estimators": 300, "max_depth": 6})
        run.log_metrics({"f1_macro": 0.94, "roc_auc": 0.98})
        run.log_confusion_matrix(y_true, y_pred, class_names)
        run.log_feature_importance(importance_dict)
        run.save_model(model, "xgboost_v1")

By experiment #20 you'll be glad everything is in one place.

MLflow UI
---------
    mlflow ui --backend-store-uri <MLFLOW_TRACKING_URI>
    # Opens http://localhost:5000
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import mlflow
import numpy as np
import pandas as pd

from src.config import MLFLOW_TRACKING_URI, MODEL_DIR, REPORT_DIR
from src.utils.logger import logger


def _git_hash() -> str:
    """Return current git commit hash (short), or 'unknown'."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _library_versions() -> dict[str, str]:
    """Return versions of key ML libraries for reproducibility."""
    libs = {}
    for name in ("sklearn", "xgboost", "optuna", "shap", "pandas", "numpy", "mlflow"):
        try:
            mod = __import__(name)
            libs[name] = getattr(mod, "__version__", "?")
        except ImportError:
            libs[name] = "not_installed"
    return libs


class RunContext:
    """
    Context manager returned by ExperimentManager.run().

    Provides a fluent API for logging everything about a training run.
    All logs automatically go to MLflow and the project logger.
    """

    def __init__(self, mlflow_run, run_name: str, dataset_scale: str) -> None:
        self._run          = mlflow_run
        self.run_name      = run_name
        self.dataset_scale = dataset_scale
        self._t_start      = time.perf_counter()

    # ── Logging API ────────────────────────────────────────────────────────────

    def log_params(self, params: dict[str, Any]) -> "RunContext":
        """Log hyperparameters."""
        mlflow.log_params(params)
        logger.info("Params: %s", params)
        return self

    def log_metrics(self, metrics: dict[str, float], step: int | None = None) -> "RunContext":
        """Log evaluation metrics."""
        mlflow.log_metrics(metrics, step=step)
        for k, v in metrics.items():
            logger.info("  %-25s %.6f", k, v)
        return self

    def log_confusion_matrix(
        self,
        y_true,
        y_pred,
        class_names: list[str] | None = None,
        title: str = "Confusion Matrix",
    ) -> "RunContext":
        """Generate, save, and log a confusion matrix plot."""
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            from sklearn.metrics import confusion_matrix

            cm = confusion_matrix(y_true, y_pred)
            labels = class_names or sorted(set(y_true))

            fig, ax = plt.subplots(figsize=(8, 6))
            sns.heatmap(
                cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=ax,
            )
            ax.set_title(title)
            ax.set_ylabel("True label")
            ax.set_xlabel("Predicted label")
            plt.tight_layout()

            path = REPORT_DIR / f"confusion_matrix_{self.run_name}.png"
            fig.savefig(path, dpi=150)
            plt.close(fig)

            mlflow.log_artifact(str(path), artifact_path="plots")
            logger.info("Confusion matrix saved → %s", path.name)
        except Exception as exc:
            logger.warning("Could not generate confusion matrix: %s", exc)
        return self

    def log_feature_importance(
        self,
        importance: dict[str, float] | None = None,
        model=None,
        feature_names: list[str] | None = None,
        top_n: int = 25,
    ) -> "RunContext":
        """
        Log feature importance as a bar chart and CSV.

        Pass either `importance` dict or (`model`, `feature_names`).
        """
        try:
            import matplotlib.pyplot as plt

            if importance is None and model is not None and feature_names is not None:
                if hasattr(model, "feature_importances_"):
                    importance = dict(zip(feature_names, model.feature_importances_))
                elif hasattr(model, "coef_"):
                    importance = dict(zip(feature_names, np.abs(model.coef_).mean(axis=0)))

            if not importance:
                return self

            # Sort and trim to top_n
            sorted_imp = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:top_n]
            names  = [x[0] for x in sorted_imp]
            values = [x[1] for x in sorted_imp]

            # Save CSV
            imp_df = pd.DataFrame(sorted_imp, columns=["feature", "importance"])
            csv_path = REPORT_DIR / f"feature_importance_{self.run_name}.csv"
            imp_df.to_csv(csv_path, index=False)
            mlflow.log_artifact(str(csv_path), artifact_path="reports")

            # Save plot
            fig, ax = plt.subplots(figsize=(10, max(6, top_n * 0.35)))
            ax.barh(names[::-1], values[::-1], color="#2196F3")
            ax.set_xlabel("Importance")
            ax.set_title(f"Top {top_n} Feature Importance — {self.run_name}")
            plt.tight_layout()

            plot_path = REPORT_DIR / f"feature_importance_{self.run_name}.png"
            fig.savefig(plot_path, dpi=150)
            plt.close(fig)
            mlflow.log_artifact(str(plot_path), artifact_path="plots")
            logger.info("Feature importance saved → %s", plot_path.name)

        except Exception as exc:
            logger.warning("Could not log feature importance: %s", exc)
        return self

    def save_model(self, model, name: str, flavor: str = "sklearn") -> Path:
        """
        Persist the model to disk and log it to MLflow.

        Parameters
        ----------
        model   : Fitted model object.
        name    : Base name (e.g. 'xgboost_v1').
        flavor  : 'sklearn' | 'xgboost' (determines MLflow logging method).

        Returns
        -------
        Path  to saved model file.
        """
        import pickle

        pkl_path = MODEL_DIR / f"{name}.pkl"
        with open(pkl_path, "wb") as f:
            pickle.dump(model, f)
        logger.info("Model saved → %s", pkl_path)

        try:
            if flavor == "xgboost":
                import mlflow.xgboost
                mlflow.xgboost.log_model(model, artifact_path="model")
            else:
                import mlflow.sklearn
                mlflow.sklearn.log_model(model, artifact_path="model")
        except Exception as exc:
            logger.warning("MLflow model logging failed: %s", exc)
            mlflow.log_artifact(str(pkl_path), artifact_path="model")

        return pkl_path

    def log_tags(self, tags: dict[str, str]) -> "RunContext":
        """Log arbitrary string tags."""
        mlflow.set_tags(tags)
        return self

    def elapsed(self) -> float:
        """Seconds since this run started."""
        return time.perf_counter() - self._t_start


class ExperimentManager:
    """
    Central interface for all ML experiment tracking.

    Usage
    -----
        manager = ExperimentManager("xgboost_baseline")

        with manager.run("trial_01") as run:
            run.log_params({...})
            run.log_metrics({...})
            run.save_model(model, "xgboost_v1")
    """

    def __init__(
        self,
        experiment_name: str = "phishing_detection",
        tracking_uri: str | None = None,
    ) -> None:
        self.experiment_name = experiment_name
        self.tracking_uri    = tracking_uri or MLFLOW_TRACKING_URI

        mlflow.set_tracking_uri(self.tracking_uri)
        mlflow.set_experiment(experiment_name)
        logger.info("MLflow tracking → %s", self.tracking_uri)
        logger.info("Experiment: %s", experiment_name)

    @contextmanager
    def run(self, run_name: str, dataset_scale: str = "100k"):
        """
        Context manager for a single training run.

        Automatically logs:
          - git commit hash
          - Python version
          - Key library versions
          - Dataset scale
          - Training duration

        Usage
        -----
            with manager.run("xgb_trial_01", dataset_scale="100k") as run:
                run.log_params(...)
                run.log_metrics(...)
        """
        logger.info("Starting run: %s", run_name)
        with mlflow.start_run(run_name=run_name) as mlflow_run:
            ctx = RunContext(mlflow_run, run_name, dataset_scale)

            # Auto-log environment
            mlflow.set_tags({
                "git_commit":     _git_hash(),
                "python_version": sys.version.split()[0],
                "platform":       platform.system(),
                "dataset_scale":  dataset_scale,
            })
            mlflow.log_params(_library_versions())

            try:
                yield ctx
            finally:
                mlflow.log_metric("training_duration_s", round(ctx.elapsed(), 2))
                logger.info("Run '%s' complete (%.1fs)", run_name, ctx.elapsed())


def print_experiment_summary(experiment_name: str = "phishing_detection") -> None:
    """Print a summary table of all runs in an experiment."""
    try:
        mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
        exp = mlflow.get_experiment_by_name(experiment_name)
        if not exp:
            print(f"No experiment named '{experiment_name}' found.")
            return

        runs = mlflow.search_runs(experiment_ids=[exp.experiment_id])
        if runs.empty:
            print("No runs logged yet.")
            return

        cols = ["run_id", "status", "start_time"]
        metric_cols = [c for c in runs.columns if c.startswith("metrics.")]
        print(runs[cols + metric_cols[:5]].to_string(index=False))
    except Exception as exc:
        logger.warning("Could not fetch run summary: %s", exc)


if __name__ == "__main__":
    # Smoke test
    manager = ExperimentManager("phishing_detection_test")
    with manager.run("smoke_test") as run:
        run.log_params({"test": True, "value": 42})
        run.log_metrics({"accuracy": 0.99, "f1_macro": 0.98})
    logger.info("MLflow smoke test complete — run 'mlflow ui' to view results.")
