"""
backend/api/routers/mlops.py
────────────────────────────
Hardened MLOps & Retraining Management Endpoints — Sprint 3 Hardened.

Endpoints:
  • POST /v1/mlops/retrain  — Trigger retraining with multi-metric promotion gate (Admin only)
  • POST /v1/mlops/rollback — Rollback to previous champion model safely (Admin only)
  • GET  /v1/mlops/status   — Retrieve active model info, zero-day counts & status (Admin only)
  • GET  /v1/mlops/models   — List model registry and available model artifacts (Admin only)
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import (
    get_current_admin,
    get_db,
    get_explainer_service,
    get_prediction_service,
)
from backend.core.config import settings
from backend.core.rate_limit import limiter
from backend.database.models import ScanResult, User
from backend.services.explainer import ExplainerService
from backend.services.learning import learning_service
from backend.services.model_lifecycle import (
    coordinate_model_reload,
    get_registry,
    model_lifecycle_lock,
)
from backend.services.prediction import PredictionService
from ml.pipelines.retrain import rollback_to_previous_champion, run_retraining_pipeline
from src.config import MODEL_DIR
from src.utils.logger import logger

router = APIRouter(prefix="/mlops", tags=["MLOps"])


class RetrainRequest(BaseModel):
    limit: int = Field(default=1000, ge=1, le=5000, description="Max zero-day samples to verify & include.")
    tune_hyperparameters: bool = Field(default=False, description="Run bounded Optuna search.")


@router.post("/retrain")
@limiter.limit("5/hour")
async def trigger_retraining(
    request: Request,
    payload: RetrainRequest = RetrainRequest(),
    db: AsyncSession = Depends(get_db),
    pred_svc: PredictionService = Depends(get_prediction_service),
    expl_svc: ExplainerService = Depends(get_explainer_service),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, Any]:
    """
    Trigger retraining pipeline using verified zero-day scans.
    Protected: Requires Admin privileges and rate limiting.
    Concurrency-Safe: Serialized across workers via model_lifecycle_lock.
    """
    if model_lifecycle_lock.is_locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A model lifecycle operation (retraining/rollback) is already active. Please wait for completion.",
        )

    try:
        async with model_lifecycle_lock:
            logger.info("Retraining initiated by admin user %s", current_admin.email)
            backup_registry = get_registry()

            X_zd, y_zd, sample_ids, provenance_map = await learning_service.build_zero_day_dataset(
                db, limit=payload.limit
            )
            n_samples = len(y_zd) if y_zd is not None else 0
            logger.info("Extracted %d verified zero-day samples for retraining.", n_samples)

            try:
                # Run pipeline in worker thread to prevent event loop blocking
                result = await asyncio.to_thread(
                    run_retraining_pipeline,
                    X_zero_day=X_zd,
                    y_zero_day=y_zd,
                    tune_hyperparameters=payload.tune_hyperparameters,
                )
            except Exception:
                logger.exception("Retraining pipeline raised an exception; resetting sample states (Finding 6).")
                await learning_service.reset_samples_from_evaluation(db, sample_ids)
                raise

            promoted = bool(result.get("promoted"))
            await learning_service.mark_samples_outcome(
                db,
                sample_ids,
                promoted=promoted,
                provenance_map=provenance_map,
            )

            if promoted:
                await asyncio.to_thread(coordinate_model_reload, pred_svc, expl_svc, backup_registry=backup_registry)
                logger.info("Prediction and Explainer services hot-reloaded with promoted champion.")

            return result
    except (RuntimeError, TimeoutError) as err:
        if "active" in str(err).lower() or "timed out" in str(err).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A model lifecycle operation (retraining/rollback) is already active. Please wait for completion.",
            ) from None
        logger.exception("Retraining execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Retraining execution failed. Please check server logs.",
        ) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("Retraining execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Retraining execution failed. Please check server logs.",
        ) from None


@router.post("/rollback")
@limiter.limit("10/hour")
async def trigger_rollback(
    request: Request,
    pred_svc: PredictionService = Depends(get_prediction_service),
    expl_svc: ExplainerService = Depends(get_explainer_service),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, Any]:
    """
    Rollback production model to previous valid champion.
    Protected: Requires Admin privileges and rate limiting.
    Concurrency-Safe: Serialized via model_lifecycle_lock.
    Non-blocking: Heavy pickle/checksum/SHAP initialization executed in threadpool (Finding 5).
    """
    if model_lifecycle_lock.is_locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A model lifecycle operation (retraining/rollback) is already active. Please wait for completion.",
        )

    try:
        async with model_lifecycle_lock:
            backup_registry = get_registry()
            result = await asyncio.to_thread(rollback_to_previous_champion)
            await asyncio.to_thread(coordinate_model_reload, pred_svc, expl_svc, backup_registry=backup_registry)
            logger.info(
                "Admin %s executed rollback to previous champion: %s",
                current_admin.email,
                result.get("current_champion"),
            )
            return result
    except (RuntimeError, TimeoutError) as err:
        if "active" in str(err).lower() or "timed out" in str(err).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A model lifecycle operation (retraining/rollback) is already active. Please wait for completion.",
            ) from None
        logger.warning("Rollback rejected: %s", err)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from None
    except (ValueError, FileNotFoundError) as err:
        logger.warning("Rollback rejected: %s", err)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from None
    except HTTPException:
        raise
    except Exception:
        logger.exception("Rollback execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rollback execution failed. Please check server logs.",
        ) from None


@router.get("/status")
@limiter.limit("60/minute")
async def get_mlops_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
    pred_svc: PredictionService = Depends(get_prediction_service),
    current_admin: User = Depends(get_current_admin),
) -> dict[str, Any]:
    """
    Get active model details, verified zero-day count, and threshold configs.
    Protected: Requires Admin privileges.
    """
    stmt_total = select(func.count(ScanResult.id)).where(ScanResult.is_zero_day.is_(True))
    res_total = await db.execute(stmt_total)
    zero_day_count = res_total.scalar() or 0

    stmt_verified = select(func.count(ScanResult.id)).where(
        ScanResult.is_zero_day.is_(True),
        ScanResult.is_retrained.is_(False),
        ScanResult.retrain_status == "VERIFIED",
        ScanResult.feature_vector.isnot(None),
    )
    res_verified = await db.execute(stmt_verified)
    verified_count = res_verified.scalar() or 0

    registry = get_registry()

    return {
        "active_model_name": pred_svc.wrapper.name if hasattr(pred_svc, "wrapper") else "Unknown",
        "active_model_file": settings.MODEL_PATH.name,
        "previous_champion": registry.get("previous_champion"),
        "last_promoted_at": registry.get("last_promoted_at"),
        "last_rollback_at": registry.get("last_rollback_at"),
        "promotion_metrics": registry.get("promotion_metrics", {}),
        "classes": getattr(pred_svc, "classes", []),
        "thresholds": getattr(pred_svc, "thresholds", {}),
        "zero_day_scans_logged": zero_day_count,
        "zero_day_verified_eligible": verified_count,
        "retrain_sample_threshold": settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD,
        "retraining_active": model_lifecycle_lock.is_locked(),
    }


@router.get("/models")
@limiter.limit("30/minute")
async def list_models(
    request: Request,
    current_admin: User = Depends(get_current_admin),
) -> dict[str, Any]:
    """
    List model registry entries and available model artifact filenames.
    Protected: Requires Admin privileges.
    """
    registry = get_registry()
    available_models = [p.name for p in MODEL_DIR.glob("*.pkl")]

    return {
        "registry": registry,
        "available_models": available_models,
    }
