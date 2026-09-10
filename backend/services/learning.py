"""
backend/services/learning.py
──────────────────────────────
Hardened Active Learning & Ground-Truth Verification Service.

Responsible for:
  1. Strict 59-Feature Schema Validation (exact count, finite numbers, no extra keys).
  2. Authoritative Ground-Truth Verification:
     - External Threat Feeds (VirusTotal, PhishTank, local blacklist).
     - Trusted Domain Allowlist (clean domains).
     - NEVER treating model predictions as ground truth.
     - Rejecting heuristic-only detections from retraining data.
  3. Explicit Retraining Lifecycle States:
     UNVERIFIED → VERIFIED → EVALUATED → PROMOTED / REJECTED / QUARANTINED.
  4. Autonomous Retraining Gating:
     Only authoritative VERIFIED samples determine the retraining threshold.
  5. Infinite Retraining Loop Prevention:
     Tracks retrain_attempt_count and quarantines failing samples after 3 attempts.
"""

from __future__ import annotations

import asyncio
import json
import math
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.database.models import ScanResult
from backend.services.model_lifecycle import (
    coordinate_model_reload,
    get_registry,
    model_lifecycle_lock,
)
from backend.services.threat_intel import TRUSTED_DOMAINS, threat_intel_service
from src.utils.logger import logger

AUTHORITATIVE_THREAT_SOURCES: set[str] = {"virustotal", "phishtank", "local_blacklist"}
MAX_RETRAIN_ATTEMPTS: int = 3


def _is_trusted_allowlist_domain(url: str) -> bool:
    """Check if the URL belongs to a verified legitimate domain in TRUSTED_DOMAINS."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return False
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in TRUSTED_DOMAINS
        )
    except Exception:
        return False


def _is_valid_feature_vector(fv: Any, expected_features: list[str]) -> bool:
    """
    Validate that a feature vector contains exactly 59 expected features,
    is strictly numeric, and contains no NaN or infinite values.
    """
    if not isinstance(fv, dict):
        return False

    if len(fv) != len(expected_features):
        return False

    for feat in expected_features:
        if feat not in fv:
            return False
        val = fv[feat]
        if not isinstance(val, int | float) or isinstance(val, bool):
            return False
        if math.isnan(val) or math.isinf(val):
            return False
    return True


class ActiveLearningService:
    def __init__(self) -> None:
        with open(settings.SCHEMA_PATH) as f:
            self.schema: list[str] = json.load(f)["features"]
        if len(self.schema) != 59:
            raise ValueError(f"ActiveLearningService: expected 59 canonical features, found {len(self.schema)}")

    async def verify_sample_label(
        self,
        url: str,
        initial_prediction: str | None = None,  # Kept for interface compatibility, never used as ground truth
    ) -> tuple[str, str] | None:
        """
        Verify ground-truth label for a zero-day URL with explicit provenance.

        Verification Rules:
        1. Authoritative Threat Intel (VirusTotal, PhishTank, local blacklist) flags threat:
           -> Verified threat label with feed provenance.
        2. Threat Intel confirms clean AND URL is on verified TRUSTED_DOMAINS allowlist:
           -> Verified 'legitimate' with 'trusted_allowlist' provenance.
        3. Model predictions alone are NEVER treated as ground truth.
        4. Heuristic-only detections without authoritative feed backing are excluded.
        5. Ambiguous or conflicting signals return None.
        """
        try:
            intel_hit = await threat_intel_service.check_url(url)
            if intel_hit:
                source = intel_hit.get("source", "unknown")
                if source in AUTHORITATIVE_THREAT_SOURCES:
                    return intel_hit["prediction"], f"{source}_detection"
                logger.debug("Rejecting heuristic-only hit for URL %s from ground-truth", url)
                return None

            # Clean in threat intel: verify against trusted allowlist
            if _is_trusted_allowlist_domain(url):
                return "legitimate", "trusted_allowlist"

            # Ambiguous: not flagged by intel, but not on trusted domain allowlist.
            # CRITICAL: Do NOT fall back to model prediction!
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to verify label for %s: %s", url, exc)
            return None

    async def process_and_verify_zero_day_sample(
        self,
        db: AsyncSession,
        scan_id: int,
        url: str,
    ) -> str:
        """
        Ingest, validate feature vector, deduplicate, and verify ground truth
        for a newly scanned zero-day URL. Updates ScanResult.retrain_status.
        """
        stmt = select(ScanResult).where(ScanResult.id == scan_id)
        res = await db.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            return "NOT_FOUND"

        # 1. Validate Feature Vector
        if not _is_valid_feature_vector(record.feature_vector, self.schema):
            record.retrain_status = "INVALID"
            await db.commit()
            logger.warning("Zero-day scan %s marked INVALID: malformed feature vector", scan_id)
            return "INVALID"

        # 2. Check Deduplication
        norm_url = url.strip().lower()
        dup_stmt = select(ScanResult.id).where(
            func.lower(ScanResult.url) == norm_url,
            ScanResult.retrain_status.in_(["VERIFIED", "EVALUATED", "PROMOTED"]),
            ScanResult.id != scan_id,
        ).limit(1)
        dup_res = await db.execute(dup_stmt)
        if dup_res.scalar_one_or_none():
            record.retrain_status = "DUPLICATE"
            await db.commit()
            logger.debug("Zero-day scan %s marked DUPLICATE for URL: %s", scan_id, url)
            return "DUPLICATE"

        # 3. Authoritative Verification
        verification = await self.verify_sample_label(url)
        if verification is None:
            record.retrain_status = "AMBIGUOUS"
            await db.commit()
            logger.debug("Zero-day scan %s marked AMBIGUOUS: no authoritative consensus", scan_id)
            return "AMBIGUOUS"

        label, provenance = verification
        record.verified_label = label
        record.label_provenance = provenance
        record.retrain_status = "VERIFIED"
        await db.commit()
        logger.info("Zero-day scan %s VERIFIED: label='%s' (provenance='%s')", scan_id, label, provenance)
        return "VERIFIED"

    async def fetch_verified_zero_day_samples(
        self,
        db: AsyncSession,
        limit: int = 1000,
    ) -> list[ScanResult]:
        """
        Fetch only VERIFIED, un-retrained zero-day scans that have not been quarantined.
        """
        stmt = (
            select(ScanResult)
            .where(
                ScanResult.is_zero_day.is_(True),
                ScanResult.is_retrained.is_(False),
                ScanResult.retrain_status == "VERIFIED",
                ScanResult.retrain_attempt_count < MAX_RETRAIN_ATTEMPTS,
                ScanResult.feature_vector.isnot(None),
            )
            .order_by(ScanResult.created_at.desc())
            .limit(limit)
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def build_zero_day_dataset(
        self,
        db: AsyncSession,
        limit: int = 1000,
    ) -> tuple[pd.DataFrame, pd.Series, list[int], dict[int, tuple[str, str]]]:
        """
        Extract verified zero-day samples into (X, y) DataFrames.
        Transitions candidate samples to 'EVALUATED' and increments attempt count.
        """
        samples = await self.fetch_verified_zero_day_samples(db, limit=limit)
        feature_rows: list[dict[str, Any]] = []
        labels: list[str] = []
        sample_ids: list[int] = []
        provenance_map: dict[int, tuple[str, str]] = {}
        now = datetime.now(timezone.utc)

        for sample in samples:
            if not _is_valid_feature_vector(sample.feature_vector, self.schema):
                sample.retrain_status = "INVALID"
                continue

            verified_label = sample.verified_label
            provenance = sample.label_provenance or "unknown"
            if not verified_label:
                continue

            # Update sample state to EVALUATED with incremented attempt
            sample.retrain_status = "EVALUATED"
            sample.retrain_attempt_count = (sample.retrain_attempt_count or 0) + 1
            sample.last_retrain_attempt = now

            sample_ids.append(sample.id)
            provenance_map[sample.id] = (verified_label, provenance)
            row = {feat: float(sample.feature_vector[feat]) for feat in self.schema}
            feature_rows.append(row)
            labels.append(verified_label)

        await db.commit()

        if not feature_rows:
            return pd.DataFrame(columns=self.schema), pd.Series(dtype=str), [], {}

        X = pd.DataFrame(feature_rows)[self.schema]
        y = pd.Series(labels, name="label")
        return X, y, sample_ids, provenance_map

    async def reset_samples_from_evaluation(
        self,
        db: AsyncSession,
        sample_ids: list[int],
    ) -> int:
        """
        Reset samples from EVALUATED back to VERIFIED if retraining pipeline
        was aborted or raised an unexpected exception. Decrements attempt count.
        Ensures samples are not permanently lost from active learning (Findings 6 & 8).
        """
        if not sample_ids:
            return 0

        stmt = select(ScanResult).where(ScanResult.id.in_(sample_ids))
        res = await db.execute(stmt)
        records = res.scalars().all()

        updated_count = 0
        for record in records:
            if record.retrain_status == "EVALUATED":
                record.retrain_status = "VERIFIED"
                record.retrain_attempt_count = max((record.retrain_attempt_count or 1) - 1, 0)
                updated_count += 1

        await db.commit()
        logger.info("Reset %d samples from EVALUATED back to VERIFIED.", updated_count)
        return updated_count

    async def mark_samples_outcome(
        self,
        db: AsyncSession,
        sample_ids: list[int],
        promoted: bool,
        provenance_map: dict[int, tuple[str, str]] | None = None,
    ) -> int:
        """
        Update sample status following candidate evaluation.
        If promoted: marks 'PROMOTED' and 'is_retrained = True'.
        If rejected: marks 'REJECTED' or 'QUARANTINED' (if max attempts reached).
        """
        if not sample_ids:
            return 0

        now = datetime.now(timezone.utc)
        stmt = select(ScanResult).where(ScanResult.id.in_(sample_ids))
        res = await db.execute(stmt)
        records = res.scalars().all()

        updated_count = 0
        for record in records:
            if promoted:
                record.is_retrained = True
                record.retrained_at = now
                record.retrain_status = "PROMOTED"
                if provenance_map and record.id in provenance_map:
                    label, prov = provenance_map[record.id]
                    record.verified_label = label
                    record.label_provenance = prov
            else:
                # Rejected candidate
                if record.retrain_attempt_count >= MAX_RETRAIN_ATTEMPTS:
                    record.retrain_status = "QUARANTINED"
                    record.is_retrained = True  # Permanently remove from future retrain pools
                    logger.warning(
                        "Sample %s QUARANTINED after %d failed retraining attempts.",
                        record.id,
                        record.retrain_attempt_count,
                    )
                else:
                    record.retrain_status = "REJECTED"

            updated_count += 1

        await db.commit()
        logger.info(
            "Updated %d samples with outcome (promoted=%s).",
            updated_count,
            promoted,
        )
        return updated_count

    async def mark_samples_retrained(
        self,
        db: AsyncSession,
        sample_ids: list[int],
        provenance_map: dict[int, tuple[str, str]],
    ) -> int:
        """Alias for backward compatibility."""
        return await self.mark_samples_outcome(db, sample_ids, promoted=True, provenance_map=provenance_map)


learning_service = ActiveLearningService()


async def check_and_trigger_autonomous_retraining(
    db_session_factory: Any = None,
    pred_svc: Any = None,
    expl_svc: Any = None,
) -> bool:
    """
    Autonomous Retraining Policy Checker & Dispatcher.
    Evaluates policy:
      1. settings.MLOPS_AUTO_RETRAIN_ENABLED must be True.
      2. Concurrency lock must not be active.
      3. Cooldown interval (settings.RETRAIN_COOLDOWN_HOURS) must be satisfied.
      4. Number of VERIFIED, un-retrained zero-day scans >= settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD.

    If all pass:
      Acquires model_lifecycle_lock, builds verified dataset, runs retraining pipeline,
      updates sample outcomes, and coordinates model reload.
    """
    if not settings.MLOPS_AUTO_RETRAIN_ENABLED:
        return False

    if model_lifecycle_lock.is_locked():
        logger.debug("Autonomous retraining skipped: lifecycle lock is active.")
        return False

    # Check cooldown against registry last_promoted_at
    registry = get_registry()
    last_promoted = registry.get("last_promoted_at")
    if last_promoted:
        try:
            promoted_dt = datetime.fromisoformat(last_promoted.replace("Z", "+00:00"))
            elapsed_hours = (datetime.now(timezone.utc) - promoted_dt).total_seconds() / 3600.0
            if elapsed_hours < settings.RETRAIN_COOLDOWN_HOURS:
                logger.debug(
                    "Autonomous retraining skipped: cooldown in effect (%.1f / %d hours).",
                    elapsed_hours,
                    settings.RETRAIN_COOLDOWN_HOURS,
                )
                return False
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not check cooldown timestamp: %s", e)

    if db_session_factory is None:
        from backend.database.session import AsyncSessionLocal

        db_session_factory = AsyncSessionLocal

    # 1. Shortened DB session: Check threshold and extract verified dataset (Finding 7)
    async with db_session_factory() as db_prep:
        stmt = select(func.count(ScanResult.id)).where(
            ScanResult.is_zero_day.is_(True),
            ScanResult.is_retrained.is_(False),
            ScanResult.retrain_status == "VERIFIED",
            ScanResult.retrain_attempt_count < MAX_RETRAIN_ATTEMPTS,
            ScanResult.feature_vector.isnot(None),
        )
        res = await db_prep.execute(stmt)
        verified_count = res.scalar() or 0

        if verified_count < settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD:
            logger.debug(
                "Autonomous retraining policy not met: %d / %d verified samples.",
                verified_count,
                settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD,
            )
            return False

        logger.info(
            "Autonomous retraining policy TRIGGERED: %d verified samples reached (threshold: %d).",
            verified_count,
            settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD,
        )

        X_zd, y_zd, sample_ids, provenance_map = await learning_service.build_zero_day_dataset(
            db_prep, limit=settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD * 2
        )

        # Handle abort path: reset samples back to VERIFIED so they are not permanently lost (Finding 8)
        if len(y_zd) < settings.RETRAIN_ZERO_DAY_SAMPLE_THRESHOLD:
            logger.info(
                "Autonomous retraining aborted: only %d verified samples extracted.",
                len(y_zd),
            )
            await learning_service.reset_samples_from_evaluation(db_prep, sample_ids)
            return False

    # 2. Pipeline execution outside DB session with exception recovery (Findings 6 & 7)
    async with model_lifecycle_lock:
        from ml.pipelines.retrain import run_retraining_pipeline

        backup_registry = get_registry()

        try:
            result = await asyncio.to_thread(
                run_retraining_pipeline,
                X_zero_day=X_zd,
                y_zero_day=y_zd,
                experiment_name="autonomous_retraining",
            )
            promoted = bool(result.get("promoted"))
        except Exception:
            logger.exception("Autonomous retraining execution failed with exception; restoring sample states.")
            async with db_session_factory() as db_err:
                await learning_service.reset_samples_from_evaluation(db_err, sample_ids)
            raise

        async with db_session_factory() as db_post:
            await learning_service.mark_samples_outcome(
                db_post,
                sample_ids,
                promoted=promoted,
                provenance_map=provenance_map,
            )

        if promoted and pred_svc and expl_svc:
            await asyncio.to_thread(coordinate_model_reload, pred_svc, expl_svc, backup_registry=backup_registry)
            logger.info("Autonomous retraining successfully promoted and synchronized new champion.")

        return promoted
