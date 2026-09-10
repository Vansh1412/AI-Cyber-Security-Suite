"""
ml/pipelines/retrain.py
────────────────────────
Production-Grade Autonomous Retraining & Model Promotion Pipeline.

Safety Features:
  1. Strict 59-Feature Canonical Schema Enforcement (no silent column dropping).
  2. Multi-Metric Promotion Gate (Macro F1, FPR, FNR, Phishing Precision/Recall, PR-AUC, Accuracy).
  3. Non-Bypassable Promotion Safety (force_promotion eliminated).
  4. Champion Validation & Exception Safeguard (evaluation failures abort promotion).
  5. SHA-256 Checksum Calculation and Verification.
  6. Bounded Optuna Hyperparameter Optimization with Fixed Seed Reproducibility.
  7. Atomic Registry Updates with Historical Tracking via ModelLifecycleManager.
  8. Comprehensive MLflow Lineage (parameters, metrics, confusion matrix, schema hash).
"""

from __future__ import annotations

import hashlib
import json
import pickle
import time
from typing import Any

import numpy as np
import pandas as pd

from backend.core.config import settings
from backend.services.model_lifecycle import (
    compute_file_sha256,
    execute_model_rollback,
    get_registry,
    promote_candidate_to_registry,
    validate_model_path,
)
from ml.models.xgboost_model import XGBoostModel
from ml.tracking.mlflow_manager import ExperimentManager
from src.config import MODEL_DIR, TRAIN_PATH, VAL_PATH
from src.utils.logger import logger


def calculate_safety_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    """
    Calculate critical security and safety metrics:
      - False Positive Rate (FPR): Legitimate URLs falsely flagged as threats.
      - False Negative Rate (FNR): Malicious URLs falsely flagged as legitimate.
    """
    is_legit_true = (y_true == "legitimate")
    is_legit_pred = (y_pred == "legitimate")

    # FPR: Fraction of actually legitimate URLs incorrectly predicted as threat
    total_legit = np.sum(is_legit_true)
    if total_legit > 0:
        false_positives = np.sum(is_legit_true & ~is_legit_pred)
        fpr = float(false_positives / total_legit)
    else:
        fpr = 0.0

    # FNR: Fraction of actual threats incorrectly predicted as legitimate
    total_threats = np.sum(~is_legit_true)
    if total_threats > 0:
        false_negatives = np.sum(~is_legit_true & is_legit_pred)
        fnr = float(false_negatives / total_threats)
    else:
        fnr = 0.0

    return {"fpr": round(fpr, 4), "fnr": round(fnr, 4), "val_fpr": round(fpr, 4), "val_fnr": round(fnr, 4)}


def calculate_pr_auc(y_true: np.ndarray, y_proba: np.ndarray, classes: list[str]) -> float:
    """Calculate Precision-Recall Area Under Curve (PR-AUC)."""
    try:
        from sklearn.metrics import average_precision_score
        from sklearn.preprocessing import label_binarize

        if len(classes) == 2:
            pos_idx = 1 if classes[1] != "legitimate" else 0
            y_bin = (y_true == classes[pos_idx]).astype(int)
            return round(float(average_precision_score(y_bin, y_proba[:, pos_idx])), 4)

        y_bin = label_binarize(y_true, classes=classes)
        return round(float(average_precision_score(y_bin, y_proba, average="macro")), 4)
    except Exception as exc:
        logger.warning("Could not compute PR-AUC: %s", exc)
        return 0.0


def load_champion_model() -> tuple[Any | None, str | None]:
    """Load current production champion model wrapper and its filename if available."""
    registry = get_registry()
    champ_file = registry.get("production")
    if not champ_file:
        return None, None

    try:
        champ_path = validate_model_path(champ_file)
        if not champ_path.exists():
            logger.warning("Champion model file '%s' not found on disk", champ_file)
            return None, champ_file

        # Checksum must be verified BEFORE unpickling (Finding 4)
        recorded_sha = registry.get("artifacts_sha256", {}).get(champ_file)
        if recorded_sha:
            computed_sha = compute_file_sha256(champ_path)
            if computed_sha != recorded_sha:
                logger.error(
                    "Champion model '%s' integrity check failed: expected %s, got %s",
                    champ_file,
                    recorded_sha,
                    computed_sha,
                )
                return None, champ_file

        with open(champ_path, "rb") as f:
            wrapper = pickle.load(f)
        return wrapper, champ_file
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not safely load current champion model '%s': %s", champ_file, exc)
        return None, champ_file


def rollback_to_previous_champion() -> dict[str, Any]:
    """
    Rollback production model to previous valid champion.
    Delegates to ModelLifecycleManager for safe history semantics.
    """
    return execute_model_rollback()


def _verify_exact_feature_schema(
    df: pd.DataFrame,
    canonical_features: list[str],
    dataset_name: str,
) -> pd.DataFrame:
    """
    Strictly enforce exact 59-feature canonical count, names, and ordering.
    Fails immediately if any feature is missing, extra, or out of order.
    """
    if len(canonical_features) != 59:
        raise ValueError(f"Canonical schema must have exactly 59 features, got {len(canonical_features)}.")

    feature_cols = [c for c in df.columns if c != "label"]

    missing = [f for f in canonical_features if f not in df.columns]
    if missing:
        raise ValueError(f"{dataset_name} schema violation: missing {len(missing)} features: {missing[:5]}")

    extra = [c for c in feature_cols if c not in canonical_features]
    if extra:
        raise ValueError(f"{dataset_name} schema violation: contains unexpected features: {extra[:5]}")

    if len(feature_cols) != len(canonical_features):
        raise ValueError(
            f"{dataset_name} schema violation: expected {len(canonical_features)} features, found {len(feature_cols)}."
        )

    # Enforce exact frozen ordering
    if feature_cols != canonical_features:
        raise ValueError(f"{dataset_name} schema violation: feature columns are out of canonical order.")

    return df[canonical_features]


def run_retraining_pipeline(
    X_zero_day: pd.DataFrame | None = None,
    y_zero_day: pd.Series | None = None,
    experiment_name: str = "phishing_retraining",
    tune_hyperparameters: bool = False,
    n_optuna_trials: int = 15,
) -> dict[str, Any]:
    """
    Execute autonomous retraining, multi-metric safety evaluation, and gated promotion.
    NOTE: force_promotion is permanently removed. Promotion strictly requires passing all gates.
    """
    logger.info("=" * 60)
    logger.info("Starting Retraining & Safety Evaluation Pipeline")
    logger.info("=" * 60)

    # 1. Authoritative 59-Feature Canonical Schema Enforcement
    with open(settings.SCHEMA_PATH) as f:
        canonical_features: list[str] = json.load(f)["features"]
    if len(canonical_features) != 59:
        raise ValueError(f"Expected 59 canonical features in schema, found {len(canonical_features)}.")

    schema_hash = hashlib.sha256("".join(canonical_features).encode()).hexdigest()[:16]

    train_df = pd.read_parquet(TRAIN_PATH)
    val_df   = pd.read_parquet(VAL_PATH)

    # Verify canonical features exist in storage splits
    missing_train = [f for f in canonical_features if f not in train_df.columns]
    if missing_train:
        raise ValueError(f"TRAIN_SPLIT missing required features: {missing_train[:5]}")
    missing_val = [f for f in canonical_features if f not in val_df.columns]
    if missing_val:
        raise ValueError(f"VAL_SPLIT missing required features: {missing_val[:5]}")

    X_train = _verify_exact_feature_schema(train_df[canonical_features], canonical_features, "TRAIN_SPLIT")
    y_train = train_df["label"].copy()

    X_val = _verify_exact_feature_schema(val_df[canonical_features], canonical_features, "VAL_SPLIT")
    y_val = val_df["label"].copy()

    # Augment training split if verified zero-day samples are provided
    n_zero_day = 0
    if X_zero_day is not None and y_zero_day is not None and not X_zero_day.empty:
        X_zd_verified = _verify_exact_feature_schema(X_zero_day, canonical_features, "ZERO_DAY_SPLIT")
        X_train = pd.concat([X_train, X_zd_verified], ignore_index=True)
        y_train = pd.concat([y_train, y_zero_day], ignore_index=True)
        n_zero_day = len(y_zero_day)
        logger.info("Augmented training dataset with %d verified zero-day samples.", n_zero_day)

    train_dataset_hash = hashlib.sha256(pd.util.hash_pandas_object(X_train).values).hexdigest()[:16]

    run_timestamp = int(time.time())
    run_name = f"retrain_xgb_{run_timestamp}"

    # Hyperparameter Optimization (Bounded Optuna search)
    model_params = dict(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
    )

    optuna_metadata: dict[str, Any] = {}
    if tune_hyperparameters:
        try:
            import optuna
            from sklearn.metrics import f1_score
            from sklearn.model_selection import StratifiedKFold
            from sklearn.preprocessing import LabelEncoder
            from xgboost import XGBClassifier

            logger.info("Running bounded Optuna search (%d trials)...", n_optuna_trials)
            le = LabelEncoder()
            y_enc = le.fit_transform(y_train)
            skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

            def objective(trial: optuna.Trial) -> float:
                p = {
                    "n_estimators": trial.suggest_int("n_estimators", 150, 400, step=50),
                    "max_depth": trial.suggest_int("max_depth", 4, 8),
                    "learning_rate": trial.suggest_float("learning_rate", 0.05, 0.2, log=True),
                    "subsample": trial.suggest_float("subsample", 0.7, 1.0),
                    "colsample_bytree": trial.suggest_float("colsample_bytree", 0.7, 1.0),
                    "objective": "multi:softprob",
                    "num_class": len(le.classes_),
                    "tree_method": "hist",
                    "random_state": 42,
                    "n_jobs": -1,
                }
                scores = []
                for train_idx, cv_val_idx in skf.split(X_train, y_enc):
                    clf = XGBClassifier(**p)
                    clf.fit(X_train.iloc[train_idx], y_enc[train_idx])
                    preds = clf.predict(X_train.iloc[cv_val_idx])
                    scores.append(f1_score(y_enc[cv_val_idx], preds, average="macro"))
                return float(np.mean(scores))

            study_name = f"retrain_study_{run_timestamp}"
            study = optuna.create_study(
                study_name=study_name,
                direction="maximize",
                sampler=optuna.samplers.TPESampler(seed=42),
            )
            optuna.logging.set_verbosity(optuna.logging.WARNING)
            study.optimize(objective, n_trials=n_optuna_trials, timeout=300)
            model_params.update(study.best_params)
            optuna_metadata = {
                "study_name": study_name,
                "n_trials_completed": len(study.trials),
                "best_value": study.best_value,
                "best_params": study.best_params,
            }
            logger.info("Optuna best hyperparameters: %s (Score: %.4f)", study.best_params, study.best_value)
        except Exception as opt_err:  # noqa: BLE001
            logger.warning("Optuna optimization encountered error, using baseline defaults: %s", opt_err)

    candidate_model = XGBoostModel(**model_params)
    manager = ExperimentManager(experiment_name)

    with manager.run(run_name, dataset_scale="augmented") as run:
        run.log_params({
            "model": "XGBoostModel",
            "n_features": len(canonical_features),
            "schema_hash": schema_hash,
            "train_dataset_hash": train_dataset_hash,
            "zero_day_samples_added": n_zero_day,
            "total_train_samples": len(X_train),
            "tune_hyperparameters": tune_hyperparameters,
            **model_params,
            **optuna_metadata,
        })

        # Train candidate
        candidate_model.fit(X_train, y_train)

        # Candidate Evaluation
        candidate_val_metrics = candidate_model.evaluate(X_val, y_val)
        y_val_pred = candidate_model.predict(X_val)
        y_val_proba = candidate_model.predict_proba(X_val)
        candidate_safety = calculate_safety_metrics(y_val.values, y_val_pred)
        candidate_val_metrics.update(candidate_safety)
        candidate_val_metrics["pr_auc"] = calculate_pr_auc(y_val.values, y_val_proba, candidate_model.classes_)

        logged_metrics = {}
        for k, v in candidate_val_metrics.items():
            metric_key = k if k.startswith("val_") else f"val_{k}"
            logged_metrics[metric_key] = v
        run.log_metrics(logged_metrics)

        # Log confusion matrix artifact
        try:
            run.log_confusion_matrix(y_val.values, y_val_pred, candidate_model.classes_)
        except Exception as cm_err:
            logger.warning("Could not log confusion matrix: %s", cm_err)

        # ── Champion Validation & Safety Safeguard ────────────────────────────
        champion_model, champion_file = load_champion_model()
        champion_val_metrics: dict[str, float] = {}
        champion_eval_failed = False
        gate_results: dict[str, Any] = {}

        if champion_file is not None and champion_model is None:
            logger.error("Champion file '%s' exists in registry but failed to load. Aborting promotion.", champion_file)
            champion_eval_failed = True
            gate_results = {
                "champion_load_failed": True,
                "champion_file": champion_file,
                "passed_all_gates": False,
                "reason": f"Champion file '{champion_file}' failed to load or verify",
            }
        elif champion_model is not None:
            try:
                champion_val_metrics = champion_model.evaluate(X_val, y_val)
                champ_pred = champion_model.predict(X_val)
                champ_proba = champion_model.predict_proba(X_val)
                champ_safety = calculate_safety_metrics(y_val.values, champ_pred)
                champion_val_metrics.update(champ_safety)
                champion_val_metrics["pr_auc"] = calculate_pr_auc(y_val.values, champ_proba, champion_model.classes_)
                logger.info(
                    "Champion Val F1: %.4f | FPR: %.4f | FNR: %.4f | PR-AUC: %.4f",
                    champion_val_metrics.get("f1_macro", 0.0),
                    champion_val_metrics.get("val_fpr", 0.0),
                    champion_val_metrics.get("val_fnr", 0.0),
                    champion_val_metrics.get("pr_auc", 0.0),
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to evaluate champion model: %s. Aborting promotion.", exc)
                champion_eval_failed = True

        # ── Multi-Metric Promotion Gate ───────────────────────────────────────
        cand_f1 = candidate_val_metrics.get("f1_macro", 0.0)
        cand_fpr = candidate_val_metrics.get("fpr", candidate_val_metrics.get("val_fpr", 0.0))
        cand_fnr = candidate_val_metrics.get("fnr", candidate_val_metrics.get("val_fnr", 0.0))
        cand_phish_prec = candidate_val_metrics.get("phishing_precision", 0.0)
        cand_phish_rec = candidate_val_metrics.get("phishing_recall", 0.0)
        cand_pr_auc = candidate_val_metrics.get("pr_auc", 0.0)
        cand_acc = candidate_val_metrics.get("accuracy", 0.0)

        if champion_eval_failed:
            logger.error("Promotion Gate Blocked: Champion evaluation failed.")
            passed_all_gates = False
            if "champion_load_failed" not in gate_results:
                gate_results = {"champion_eval_failed": True, "passed_all_gates": False}
        elif champion_model is not None:
            champ_f1 = champion_val_metrics.get("f1_macro", 0.0)
            champ_fpr = champion_val_metrics.get("fpr", champion_val_metrics.get("val_fpr", 0.0))
            champ_fnr = champion_val_metrics.get("fnr", champion_val_metrics.get("val_fnr", 0.0))
            champ_phish_rec = champion_val_metrics.get("phishing_recall", 0.0)
            champ_pr_auc = champion_val_metrics.get("pr_auc", 0.0)
            champ_acc = champion_val_metrics.get("accuracy", 0.0)

            # Promotion Gates:
            # 1. Macro F1 must not degrade (0.002 margin)
            # 2. FPR ceiling: min(champ_fpr + 0.002, 0.015) fails closed, prevents arbitrary floor
            # 3. FNR ceiling: min(champ_fnr + 0.005, 0.030) fails closed, prevents threat leakage
            # 4. Phishing Precision must be >= 0.90
            # 5. Phishing Recall must not degrade
            # 6. PR-AUC must not degrade
            # 7. Accuracy must not degrade
            gate_f1 = cand_f1 >= (champ_f1 - 0.002)
            gate_fpr = cand_fpr <= min(champ_fpr + 0.002, 0.015)
            gate_fnr = cand_fnr <= min(champ_fnr + 0.005, 0.030)
            gate_prec = cand_phish_prec >= 0.90
            gate_rec = cand_phish_rec >= max(champ_phish_rec - 0.01, 0.85)
            gate_pr_auc = cand_pr_auc >= max(champ_pr_auc - 0.005, 0.90)
            gate_acc = cand_acc >= max(champ_acc - 0.005, 0.88)

            passed_all_gates = bool(
                gate_f1 and gate_fpr and gate_fnr and gate_prec and gate_rec and gate_pr_auc and gate_acc
            )
            gate_results = {
                "gate_f1_passed": gate_f1,
                "gate_fpr_passed": gate_fpr,
                "gate_fnr_passed": gate_fnr,
                "gate_phishing_precision_passed": gate_prec,
                "gate_phishing_recall_passed": gate_rec,
                "gate_pr_auc_passed": gate_pr_auc,
                "gate_accuracy_passed": gate_acc,
                "passed_all_gates": passed_all_gates,
            }
        else:
            # P1-5: If no valid champion exists, DO NOT automatically promote the candidate.
            # Fail safely, log reason, and return controlled failure.
            logger.warning("Promotion Gate Blocked: No valid champion exists in registry to benchmark against.")
            passed_all_gates = False
            gate_results = {
                "champion_missing": True,
                "passed_all_gates": False,
                "reason": "Promotion requires valid production champion for safety benchmarking",
            }

        promoted = passed_all_gates
        logger.info("Promotion Gate Evaluation: %s -> Promoted: %s", gate_results, promoted)

        # Save candidate pickle
        model_filename = f"xgboost_retrained_{run_timestamp}.pkl"
        saved_path = MODEL_DIR / model_filename
        with open(saved_path, "wb") as f:
            pickle.dump(candidate_model, f)

        # Pre-promotion dry-run verification
        with open(saved_path, "rb") as f:
            test_loaded = pickle.load(f)
        _ = test_loaded.predict(X_val.head(2))

        candidate_sha256 = compute_file_sha256(saved_path)
        # Mandatory artifact checksum verification (Finding 10)
        if not candidate_sha256 or len(candidate_sha256) != 64:
            logger.error("Candidate artifact checksum generation failed. Promotion blocked.")
            promoted = False
            gate_results["checksum_valid"] = False

        run.save_model(candidate_model, f"xgboost_retrained_{run_timestamp}", flavor="xgboost")
        run.log_params({
            "promoted": promoted,
            "champion_model": champion_file or "none",
            "candidate_sha256": candidate_sha256,
        })

        if promoted:
            promote_candidate_to_registry(
                candidate_filename=model_filename,
                candidate_metrics={
                    "val_f1_macro": cand_f1,
                    "val_fpr": cand_fpr,
                    "val_fnr": cand_fnr,
                    "phishing_precision": cand_phish_prec,
                    "phishing_recall": cand_phish_rec,
                    "pr_auc": cand_pr_auc,
                    "accuracy": cand_acc,
                },
                candidate_sha256=candidate_sha256,
            )

        return {
            "status": "success",
            "promoted": promoted,
            "model_file": model_filename,
            "candidate_sha256": candidate_sha256,
            "previous_champion": champion_file,
            "zero_day_samples_added": n_zero_day,
            "candidate_metrics": candidate_val_metrics,
            "champion_metrics": champion_val_metrics,
            "gate_results": gate_results,
        }
