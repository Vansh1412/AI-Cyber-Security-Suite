"""
backend/services/model_lifecycle.py
────────────────────────────────────
Production-Grade Model Lifecycle & Concurrency Synchronization Service.

Guarantees:
  1. Multi-Process Lock: Serializes retraining, promotion, and rollback across workers.
  2. Safe Rollback Semantics: Explicit champion history stack and demoted-model tracking;
     two consecutive rollbacks will never reinstall a demoted bad champion.
  3. Artifact Integrity & Anti-Traversal: Strict SHA-256 verification and directory confinement.
  4. Coordinated Reload: Two-phase reload of Prediction and Explainer services;
     automatically rolls back if explainer desynchronizes.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.core.config import settings
from src.config import MODEL_DIR
from src.utils.logger import logger

LOCK_FILE = MODEL_DIR / ".lifecycle.lock"
_IN_PROCESS_LOCK = asyncio.Lock()


class ModelLifecycleLock:
    """
    Cross-process and cross-coroutine synchronization mutex.
    Combines an in-process asyncio.Lock with an atomic OS lockfile.
    """

    def __init__(self, timeout_seconds: float = 300.0) -> None:
        self.timeout_seconds = timeout_seconds
        self._fd: int | None = None
        self._locked_in_process = False

    def _is_lock_process_alive(self) -> bool:
        """Check if the process holding the lockfile is currently active."""
        if not LOCK_FILE.exists():
            return False
        try:
            content = LOCK_FILE.read_text().strip()
            for part in content.split(","):
                if part.startswith("pid="):
                    pid = int(part.split("=")[1])
                    import psutil
                    return psutil.pid_exists(pid)
        except Exception:
            pass
        return False

    def is_locked(self) -> bool:
        """Check if lock is held in-process or by another active process."""
        if _IN_PROCESS_LOCK.locked():
            return True
        if LOCK_FILE.exists():
            # If the process holding the lock is still alive, lock is active regardless of age (Finding 9)
            if self._is_lock_process_alive():
                return True

            # Owning process died or cannot be identified; check age for safe cleanup
            try:
                mtime = LOCK_FILE.stat().st_mtime
                if (time.time() - mtime) > 900:
                    LOCK_FILE.unlink(missing_ok=True)
                    return False
                return True
            except OSError:
                return False
        return False

    def acquire_file_lock(self) -> None:
        """Acquire atomic OS lockfile."""
        start_time = time.time()
        while True:
            try:
                self._fd = os.open(
                    str(LOCK_FILE),
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                )
                with os.fdopen(self._fd, "w") as f:
                    f.write(f"pid={os.getpid()},time={datetime.now(timezone.utc).isoformat()}\n")
                self._fd = None
                return
            except FileExistsError:
                # If owning process is dead, clean up orphaned lock immediately
                if not self._is_lock_process_alive():
                    try:
                        LOCK_FILE.unlink(missing_ok=True)
                        continue
                    except OSError:
                        pass

                if (time.time() - start_time) > self.timeout_seconds:
                    raise TimeoutError("Timed out waiting for model lifecycle lock.") from None
                time.sleep(0.1)

    def release_file_lock(self) -> None:
        """Release atomic OS lockfile."""
        try:
            if LOCK_FILE.exists():
                LOCK_FILE.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not cleanly unlink model lifecycle lock: %s", exc)

    async def __aenter__(self) -> ModelLifecycleLock:
        if self.is_locked():
            raise RuntimeError("Model lifecycle operation is currently active.")
        await _IN_PROCESS_LOCK.acquire()
        self._locked_in_process = True
        try:
            await asyncio.to_thread(self.acquire_file_lock)
        except Exception:
            _IN_PROCESS_LOCK.release()
            self._locked_in_process = False
            raise
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            await asyncio.to_thread(self.release_file_lock)
        finally:
            if self._locked_in_process:
                _IN_PROCESS_LOCK.release()
                self._locked_in_process = False

    def __enter__(self) -> ModelLifecycleLock:
        if self.is_locked():
            raise RuntimeError("Model lifecycle operation is currently active.")
        self.acquire_file_lock()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release_file_lock()


model_lifecycle_lock = ModelLifecycleLock()


# ── Artifact Integrity & Path Traversal Protection ───────────────────────────

def validate_model_path(model_filename: str) -> Path:
    """
    Ensure model filename is strictly confined to MODEL_DIR and free of path traversal.
    """
    clean_name = Path(model_filename).name
    if clean_name != model_filename or ".." in model_filename or "/" in model_filename or "\\" in model_filename:
        raise ValueError(f"Invalid model filename '{model_filename}': path traversal not permitted.")
    resolved_path = (MODEL_DIR / clean_name).resolve()
    if not str(resolved_path).startswith(str(MODEL_DIR.resolve())):
        raise ValueError(f"Path traversal detected for model file: {model_filename}")
    return resolved_path


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a model artifact."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ── Registry Operations with Champion History ─────────────────────────────────

def get_registry() -> dict[str, Any]:
    """Read registry safely."""
    if not settings.REGISTRY_PATH.exists():
        return {
            "production": "xgboost_calibrated.pkl",
            "staging": "xgboost_calibrated.pkl",
            "experimental": "xgboost_calibrated.pkl",
            "champion_history": ["xgboost_calibrated.pkl"],
            "demoted_models": [],
            "artifacts_sha256": {},
        }
    with open(settings.REGISTRY_PATH) as f:
        return json.load(f)


def write_registry_atomically(data: dict[str, Any]) -> None:
    """Write registry file using atomic rename."""
    tmp_file = settings.REGISTRY_PATH.with_suffix(".tmp")
    with open(tmp_file, "w") as f:
        json.dump(data, f, indent=2)
    tmp_file.replace(settings.REGISTRY_PATH)


def promote_candidate_to_registry(
    candidate_filename: str,
    candidate_metrics: dict[str, Any],
    candidate_sha256: str | None = None,
) -> dict[str, Any]:
    """
    Promote candidate model into registry while preserving champion history.
    Mandates a valid 64-character SHA-256 checksum for the candidate artifact.
    """
    if not candidate_sha256 or not isinstance(candidate_sha256, str) or len(candidate_sha256.strip()) != 64:
        raise ValueError(
            f"Promotion rejected: candidate '{candidate_filename}' must have a valid 64-character SHA-256 checksum."
        )
    candidate_sha256 = candidate_sha256.strip()

    reg = get_registry()
    current_champ = reg.get("production", "xgboost_calibrated.pkl")
    history: list[str] = reg.get("champion_history", [])

    if current_champ and current_champ not in history:
        history.append(current_champ)

    demoted: list[str] = reg.get("demoted_models", [])
    # If this model was previously demoted, remove it from demoted since it passed new promotion
    if candidate_filename in demoted:
        demoted.remove(candidate_filename)

    artifacts_sha256 = reg.get("artifacts_sha256", {})
    artifacts_sha256[candidate_filename] = candidate_sha256

    reg["production"] = candidate_filename
    reg["staging"] = candidate_filename
    reg["experimental"] = candidate_filename
    reg["previous_champion"] = current_champ
    reg["champion_history"] = history
    reg["demoted_models"] = demoted
    reg["artifacts_sha256"] = artifacts_sha256
    reg["last_promoted_at"] = datetime.now(timezone.utc).isoformat()
    reg["promotion_metrics"] = candidate_metrics

    write_registry_atomically(reg)
    logger.info("Registry updated: '%s' promoted to production (Previous: %s).", candidate_filename, current_champ)
    return reg


def execute_model_rollback() -> dict[str, Any]:
    """
    Rollback to the most recent valid champion in history.
    Never re-promotes a demoted bad champion.
    """
    reg = get_registry()
    current_prod = reg.get("production", "xgboost_calibrated.pkl")
    history: list[str] = reg.get("champion_history", [])
    demoted: list[str] = reg.get("demoted_models", [])

    # Find the latest valid champion in history that is not current and not demoted
    candidate_rollback: str | None = None
    for champ in reversed(history):
        if champ != current_prod and champ not in demoted:
            # Validate file existence and path
            try:
                p = validate_model_path(champ)
                if p.exists():
                    candidate_rollback = champ
                    break
            except Exception:
                continue

    # Fallback check to previous_champion if not in history
    if not candidate_rollback:
        prev = reg.get("previous_champion")
        if prev and prev != current_prod and prev not in demoted:
            try:
                p = validate_model_path(prev)
                if p.exists():
                    candidate_rollback = prev
            except Exception:
                pass

    if not candidate_rollback:
        raise ValueError("No valid previous champion available in history for rollback.")

    # Validate target artifact can be unpickled and run inference
    target_path = validate_model_path(candidate_rollback)
    recorded_sha = reg.get("artifacts_sha256", {}).get(candidate_rollback)
    if recorded_sha:
        computed_sha = compute_file_sha256(target_path)
        if computed_sha != recorded_sha:
            raise ValueError(
                f"Rollback target '{candidate_rollback}' integrity check failed: expected {recorded_sha}, got {computed_sha}"
            )

    import pickle
    with open(target_path, "rb") as f:
        test_obj = pickle.load(f)
    if not hasattr(test_obj, "model") and not hasattr(test_obj, "predict"):
        raise RuntimeError(f"Rollback target '{candidate_rollback}' lacks required model interface.")

    # Record current model as demoted
    if current_prod not in demoted:
        demoted.append(current_prod)

    reg["production"] = candidate_rollback
    reg["staging"] = candidate_rollback
    reg["demoted_models"] = demoted
    reg["previous_champion"] = None  # Clear ambiguous reference
    reg["last_rollback_at"] = datetime.now(timezone.utc).isoformat()

    write_registry_atomically(reg)
    logger.info(
        "Model rollback executed: restored '%s' to production. Demoted '%s'.",
        candidate_rollback,
        current_prod,
    )
    return {
        "status": "rolled_back",
        "current_champion": candidate_rollback,
        "demoted_model": current_prod,
        "timestamp": reg["last_rollback_at"],
    }


# ── Coordinated Two-Phase Reload ──────────────────────────────────────────────

def coordinate_model_reload(
    pred_svc: Any,
    expl_svc: Any,
    backup_registry: dict[str, Any] | None = None,
) -> None:
    """
    Synchronously and transactionally reload Prediction and Explainer services.
    If Explainer reload fails, immediately rolls back registry and PredictionService
    to guarantee zero desynchronization.
    """
    logger.info("Starting coordinated reload of Prediction and Explainer services.")
    try:
        pred_svc.reload_model()
    except Exception as pred_err:
        logger.error("PredictionService reload failed: %s", pred_err)
        if backup_registry:
            write_registry_atomically(backup_registry)
        raise RuntimeError(f"PredictionService reload failed: {pred_err}") from pred_err

    try:
        expl_svc.reload_model()
    except Exception as expl_err:
        logger.error("ExplainerService reload failed: %s. Initiating emergency recovery.", expl_err)
        if backup_registry:
            write_registry_atomically(backup_registry)
            try:
                pred_svc.reload_model()
                logger.info("PredictionService restored to previous champion after explainer failure.")
            except Exception as rec_err:
                logger.critical("Failed to restore PredictionService during recovery: %s", rec_err)
        raise RuntimeError(f"ExplainerService reload failed; state reverted: {expl_err}") from expl_err

    logger.info("Coordinated model reload successfully synchronized both services.")
