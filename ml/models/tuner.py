"""
ml/models/tuner.py
───────────────────
OptunaTuner — Hyperparameter optimisation for XGBoost using Optuna.

Uses stratified K-fold cross-validation on the training split.
Val and test sets are never touched during tuning.

Usage
-----
    python -m ml.models.tuner

    # Or from code:
    from ml.models.tuner import OptunaTuner
    tuner = OptunaTuner(n_trials=50)
    best_params = tuner.run()
"""

from __future__ import annotations

import sys
import time

import numpy as np
import optuna
import pandas as pd
import yaml
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from ml.models.base import load_feature_list
from ml.models.xgboost_model import train_and_log
from ml.tracking.mlflow_manager import ExperimentManager
from src.config import TRAIN_PATH, TRAINING_CONFIG
from src.utils.logger import logger

optuna.logging.set_verbosity(optuna.logging.WARNING)


def _load_config() -> dict:
    with open(TRAINING_CONFIG, "r") as f:
        return yaml.safe_load(f)


class OptunaTuner:
    """
    Optuna-based hyperparameter search for XGBoost.

    Strategy
    --------
    - StratifiedKFold (5 folds) on train.parquet
    - Objective: maximise mean val F1 (macro)
    - Each trial trains 5 models → averages F1 across folds
    - Best params are then used to retrain on full train split

    Parameters
    ----------
    n_trials : int   Number of Optuna trials (default: 50).
    timeout  : int   Max tuning time in seconds (default: 3600 = 1 hour).
    cv_folds : int   Cross-validation folds (default: 5).
    """

    def __init__(
        self,
        n_trials: int | None = None,
        timeout:  int | None = None,
        cv_folds: int | None = None,
    ) -> None:
        cfg = _load_config().get("xgboost", {})
        self.n_trials = n_trials or cfg.get("n_trials", 50)
        self.timeout  = timeout  or cfg.get("timeout_seconds", 3600)
        self.cv_folds = cv_folds or cfg.get("cv_folds", 5)
        self.best_params: dict = {}
        self.study = None

    def run(self, dataset_scale: str = "100k") -> dict:
        """
        Run the full Optuna study.

        Returns
        -------
        dict  Best hyperparameters found.
        """
        logger.info("=" * 55)
        logger.info("Optuna Tuning — %d trials, %d-fold CV", self.n_trials, self.cv_folds)
        logger.info("=" * 55)

        features = load_feature_list()
        train_df = pd.read_parquet(TRAIN_PATH)
        feat_cols = [f for f in features if f in train_df.columns]

        X = train_df[feat_cols].values
        y_str = train_df["label"].values
        le = LabelEncoder()
        y = le.fit_transform(y_str)
        n_classes = len(le.classes_)

        skf = StratifiedKFold(n_splits=self.cv_folds, shuffle=True, random_state=42)

        def objective(trial: optuna.Trial) -> float:
            params = {
                "n_estimators":     trial.suggest_int("n_estimators",    100, 600, step=50),
                "max_depth":        trial.suggest_int("max_depth",        3, 10),
                "learning_rate":    trial.suggest_float("learning_rate",  0.01, 0.3, log=True),
                "subsample":        trial.suggest_float("subsample",      0.5, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
                "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
                "gamma":            trial.suggest_float("gamma",          0.0, 5.0),
                "reg_alpha":        trial.suggest_float("reg_alpha",      1e-8, 10.0, log=True),
                "reg_lambda":       trial.suggest_float("reg_lambda",     1e-8, 10.0, log=True),
                "objective":        "multi:softprob",
                "num_class":        n_classes,
                "eval_metric":      "mlogloss",
                "tree_method":      "hist",
                "n_jobs":           -1,
                "random_state":     42,
                "use_label_encoder": False,
            }

            fold_scores = []
            for fold_i, (tr_idx, val_idx) in enumerate(skf.split(X, y)):
                clf = XGBClassifier(**params)
                clf.fit(X[tr_idx], y[tr_idx])
                y_pred = clf.predict(X[val_idx])

                from sklearn.metrics import f1_score
                f1 = f1_score(y[val_idx], y_pred, average="macro", zero_division=0)
                fold_scores.append(f1)

                trial.report(np.mean(fold_scores), step=fold_i)
                if trial.should_prune():
                    raise optuna.TrialPruned()

            return float(np.mean(fold_scores))

        self.study = optuna.create_study(
            direction="maximize",
            pruner=optuna.pruners.MedianPruner(n_startup_trials=5, n_warmup_steps=2),
        )

        t0 = time.perf_counter()
        self.study.optimize(
            objective,
            n_trials=self.n_trials,
            timeout=self.timeout,
            show_progress_bar=True,
        )

        elapsed = time.perf_counter() - t0
        best = self.study.best_trial
        self.best_params = best.params

        logger.info("Tuning complete in %.1fs — %d trials", elapsed, len(self.study.trials))
        logger.info("Best F1 (macro, CV): %.4f", best.value)
        logger.info("Best params: %s", self.best_params)

        # Retrain on full training split with best params and log to MLflow
        logger.info("Retraining with best params on full train split…")
        train_and_log(
            dataset_scale=dataset_scale,
            params=self.best_params,
            run_name="xgboost_optuna_best",
        )

        return self.best_params


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    tuner = OptunaTuner()
    best  = tuner.run()
    print("\nBest hyperparameters:")
    for k, v in best.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
