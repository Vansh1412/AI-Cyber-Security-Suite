"""
backend/services/monitoring_worker.py
─────────────────────────────────────
Sprint 5 Phase 5B: Monitoring Worker & Concurrency Execution Pool.

Responsibilities:
  1. Authoritative pre-execution lease validation:
     Verify execution_token, execution_epoch, and execution_expires_at > NOW()
     BEFORE any network socket, DNS resolution, ML inference, or event emission.
  2. Bounded concurrency & fairness:
     - Global limit: max 10 concurrent active workers.
     - Per-user limit: max 2 concurrent active workers per tenant.
     - Hard outer task timeout (30.0s) strictly inside the 45.0s DB lease.
  3. Canonical 59-feature extraction and frozen XGBoost prediction.
     - Predictions are strictly operational telemetry (never training ground truth).
     - Model unavailable/failure gracefully falls back to prediction="UNKNOWN".
  4. Monitoring outcome classification using existing 6 EventType enums:
     - Emits SecurityEvent with payload["event_subtype"].
  5. Alert deduplication via AlertService (15m window, occurrence_count increment).
  6. Idempotent incident resolution via IncidentService.get_or_create_threat_incident.
  7. Authoritative triple-predicate write-back via SchedulerService.write_back_result.
  8. Exponential failure backoff and automatic suspension after 5 consecutive failures.
  9. Sanitized audit logging via AuditEvent model.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.database.models import AuditEvent, MonitoringTarget
from backend.database.session import engine
from backend.schemas.soc import EventSeverity, EventType, IndicatorType
from backend.services.alert_service import alert_service
from backend.services.correlation_engine import correlation_engine
from backend.services.event_engine import event_engine
from backend.services.feature_eng import FeatureService
from backend.services.incident_service import incident_service
from backend.services.monitoring_probe import (
    MonitoringProbe,
    ProbeFailureCategory,
    ProbeResult,
    monitoring_probe,
)
from backend.services.prediction import PredictionService
from backend.services.scheduler_service import ClaimedTarget, scheduler_service
from src.utils.logger import logger

# ── Concurrency & Timeout Constants ────────────────────────────────────────────

GLOBAL_MAX_WORKERS: int = 10
MAX_USER_WORKERS: int = 2

WORKER_HARD_TIMEOUT_S: float = 30.0
ML_TIMEOUT_S: float = 2.0
MAX_CONSECUTIVE_FAILURES: int = 5
MAX_BACKOFF_MINUTES: int = 1440
_monitoring_async_locks: dict[tuple[int, int], asyncio.Lock] = {}
_monitoring_thread_locks: dict[int, threading.Lock] = {}
_monitoring_thread_guard = threading.Lock()


def _get_monitoring_async_lock(user_id: int) -> asyncio.Lock:
    """Return an asyncio.Lock bound to the current event loop for user_id."""
    loop = asyncio.get_running_loop()
    key = (id(loop), user_id)
    if key not in _monitoring_async_locks:
        _monitoring_async_locks[key] = asyncio.Lock()
    return _monitoring_async_locks[key]


def _get_monitoring_thread_lock(user_id: int) -> threading.Lock:
    """Return a thread-safe threading.Lock for user_id on non-PostgreSQL engines."""
    with _monitoring_thread_guard:
        if user_id not in _monitoring_thread_locks:
            _monitoring_thread_locks[user_id] = threading.Lock()
        return _monitoring_thread_locks[user_id]


# ── Monitoring Worker ──────────────────────────────────────────────────────────

class MonitoringWorker:
    """
    Executes a single monitoring target check under strict lease fencing.
    """

    def __init__(
        self,
        probe: MonitoringProbe | None = None,
        feature_service: FeatureService | None = None,
        prediction_service: PredictionService | None = None,
        session_factory: Callable[[], Session] | None = None,
    ) -> None:
        self.probe = probe or monitoring_probe
        self._feat_svc = feature_service
        self._pred_svc = prediction_service
        self._session_factory = session_factory or (lambda: Session(bind=engine.sync_engine))

    def _get_feature_service(self) -> FeatureService:
        if self._feat_svc is None:
            self._feat_svc = FeatureService()
        return self._feat_svc

    def _get_prediction_service(self) -> PredictionService:
        if self._pred_svc is None:
            self._pred_svc = PredictionService()
        return self._pred_svc

    @staticmethod
    def validate_lease(
        session: Session,
        target_id: int,
        execution_token: str,
        execution_epoch: int,
    ) -> bool:
        """
        Authoritatively validate that this worker holds the active lease in the DB.
        Succeeds only if token, epoch, and lease expiry are strictly valid NOW().
        """
        dialect = session.bind.dialect.name if session.bind else "sqlite"

        if dialect == "postgresql":
            row = session.execute(
                text(
                    "SELECT id FROM monitoring_targets "
                    "WHERE id = :target_id "
                    "  AND execution_token = :token "
                    "  AND execution_epoch = :epoch "
                    "  AND execution_expires_at > NOW()"
                ),
                {"target_id": target_id, "token": execution_token, "epoch": execution_epoch},
            ).fetchone()
            return row is not None

        # SQLite storage format comparison
        now_sqlite = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
        row = session.execute(
            text(
                "SELECT id FROM monitoring_targets "
                "WHERE id = :target_id "
                "  AND execution_token = :token "
                "  AND execution_epoch = :epoch "
                "  AND execution_expires_at > :now_sqlite"
            ),
            {
                "target_id": target_id,
                "token": execution_token,
                "epoch": execution_epoch,
                "now_sqlite": now_sqlite,
            },
        ).fetchone()
        return row is not None

    async def execute_target(self, target: ClaimedTarget) -> bool:
        """
        Execute monitoring target check with outer 30.0s hard timeout.
        Returns True if check completed and result was written back; False otherwise.
        """
        try:
            return await asyncio.wait_for(
                self._execute_target_inner(target),
                timeout=WORKER_HARD_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            logger.warning("[WORKER] Target %d exceeded hard task limit (30.0s)", target.target_id)
            return False
        except asyncio.CancelledError:
            logger.info("[WORKER] Target %d execution was cancelled during task shutdown", target.target_id)
            return False
        except Exception as exc:
            logger.error("[WORKER] Unhandled exception for target %d: %s", target.target_id, exc, exc_info=True)
            return False

    async def _execute_target_inner(self, target: ClaimedTarget) -> bool:
        """Internal execution flow strictly adhering to the 12-step lifecycle."""
        pre_sess = self._session_factory()
        try:
            # ── Step 3: Authoritative Pre-Execution Lease Check ────────────────
            is_valid = self.validate_lease(
                pre_sess,
                target_id=target.target_id,
                execution_token=target.execution_token,
                execution_epoch=target.execution_epoch,
            )
            if not is_valid:
                logger.warning(
                    "[WORKER] Stale lease detected for target %d (token=%s…, epoch=%d). "
                    "Pre-execution fencing rejected task; zero outbound I/O performed.",
                    target.target_id,
                    target.execution_token[:8],
                    target.execution_epoch,
                )
                return False

            # Query current consecutive failures count from target row
            current_target = pre_sess.execute(
                select(MonitoringTarget).where(MonitoringTarget.id == target.target_id)
            ).scalar_one_or_none()
            consecutive_failures = current_target.consecutive_failures if current_target else 0
            target_uuid = current_target.target_uuid if current_target else str(target.target_id)

        finally:
            pre_sess.close()

        # ── Step 4 & 5: SSRF-Safe Network Probe ────────────────────────────────
        probe_result: ProbeResult = await self.probe.probe(target.url)

        # ── Step 6: ML Feature Extraction & Frozen Prediction ──────────────────
        prediction = "UNKNOWN"
        confidence = 0.0

        if probe_result.success:
            try:
                prediction, confidence = await asyncio.wait_for(
                    asyncio.to_thread(self._run_inference, target.url),
                    timeout=ML_TIMEOUT_S,
                )
            except Exception as exc:
                logger.warning(
                    "[WORKER] Inference degraded for target %d (%s): %s",
                    target.target_id, target.url, exc,
                )
                prediction = "UNKNOWN"
                confidence = 0.0

        # ── Step 7: Classification & Existing EventType Mapping ────────────────
        event_type, severity, subtype, is_suspension, new_failures = self._classify_outcome(
            probe_result=probe_result,
            prediction=prediction,
            confidence=confidence,
            current_failures=consecutive_failures,
        )

        # ── Step 8, 9, 10: SOC Event, Alert & Incident Pipeline ────────────────
        now_dt = datetime.now(timezone.utc)
        event_schema = event_engine.create_event(
            event_type=event_type,
            severity=severity,
            indicator_type=IndicatorType.URL,
            indicator_value=target.url,
            user_id=target.user_id,
            payload={
                "event_subtype": subtype,
                "target_uuid": target_uuid,
                "normalized_domain": target.normalized_domain,
                "status_code": probe_result.status_code,
                "latency_ms": probe_result.latency_ms,
                "redirect_count": probe_result.redirect_count,
                "tls_valid": probe_result.tls_valid,
                "prediction": prediction,
                "confidence": confidence,
                "failure_category": probe_result.failure_category.value if probe_result.failure_category else None,
            },
            timestamp=now_dt,
        )
        event_engine.emit_event(event_schema)

        post_sess = self._session_factory()
        try:
            # Multi-factor event & alert correlation
            correlation_engine.correlate_event(post_sess, event_schema)

            # Alert and Incident integration for critical/high/SSRF threats
            if severity in (EventSeverity.CRITICAL, EventSeverity.HIGH) or subtype == "SSRF_OUTBOUND_PROBE_BLOCKED":
                tenant_id = target.user_id if target.user_id is not None else 0
                is_pg = post_sess.bind and post_sess.bind.dialect.name == "postgresql"

                async def _run_soc_pipeline() -> None:
                    if is_pg:
                        lock_key = f"MONITORING_SOC:{tenant_id}:{target.normalized_domain}"
                        post_sess.execute(
                            text("SELECT pg_advisory_xact_lock(hashtext(:key))").bindparams(key=lock_key)
                        )
                    alert_obj, _ = alert_service.process_event(
                        post_sess,
                        event_schema,
                        rule_name="MONITORING_THREAT_DETECTION",
                    )
                    post_sess.commit()

                    if severity == EventSeverity.CRITICAL or subtype == "SSRF_OUTBOUND_PROBE_BLOCKED":
                        title = f"Automated Threat Incident: {target.normalized_domain}"
                        await incident_service.get_or_create_threat_incident(
                            post_sess,
                            user_id=target.user_id,
                            normalized_domain=target.normalized_domain,
                            severity=severity.value,
                            title=title,
                            description=f"Automated monitoring detected {subtype} on target {target.normalized_domain}.",
                            initial_alert_id=alert_obj.id,
                        )

                if is_pg:
                    await _run_soc_pipeline()
                else:
                    async with _get_monitoring_async_lock(tenant_id):
                        with _get_monitoring_thread_lock(tenant_id):
                            await _run_soc_pipeline()

            # ── Step 11: Authoritative Write-Back ──────────────────────────────
            effective_interval = target.check_interval_minutes
            if new_failures > 0 and not is_suspension:
                # Exponential backoff multiplier: 2^min(failures, 5)
                multiplier = 2 ** min(new_failures, 5)
                effective_interval = min(target.check_interval_minutes * multiplier, MAX_BACKOFF_MINUTES)

            written = scheduler_service.write_back_result(
                post_sess,
                target_id=target.target_id,
                execution_token=target.execution_token,
                execution_epoch=target.execution_epoch,
                last_checked_at=now_dt,
                interval_minutes=effective_interval,
                last_prediction=prediction,
                last_confidence=confidence,
                consecutive_failures=new_failures,
            )

            if not written:
                logger.warning(
                    "[WORKER] Write-back discarded for target %d: lease expired or epoch advanced.",
                    target.target_id,
                )
                return False

            # If target auto-suspended or SSRF blocked: mark is_active=False
            if is_suspension:
                post_sess.execute(
                    text("UPDATE monitoring_targets SET is_active = :active WHERE id = :target_id"),
                    {"active": False, "target_id": target.target_id},
                )
                post_sess.commit()

            # ── Step 12: Sanitized Audit Trail ─────────────────────────────────
            audit_action = (
                "TARGET_AUTO_SUSPENDED"
                if subtype == "MONITORING_TARGET_SUSPENDED"
                else (
                    "TARGET_SSRF_ABORTED"
                    if subtype == "SSRF_OUTBOUND_PROBE_BLOCKED"
                    else "MONITORING_CHECK_EXECUTED"
                )
            )
            audit_event = AuditEvent(
                action=audit_action,
                actor_user_id=target.user_id,
                target_resource="monitoring_target",
                resource_id=target_uuid,
                details={
                    "normalized_domain": target.normalized_domain,
                    "event_subtype": subtype,
                    "prediction": prediction,
                    "confidence": confidence,
                    "status_code": probe_result.status_code,
                    "latency_ms": probe_result.latency_ms,
                    "consecutive_failures": new_failures,
                    "is_active": not is_suspension,
                },
                created_at=now_dt,
            )
            post_sess.add(audit_event)
            post_sess.commit()
            return True

        finally:
            post_sess.close()

    def _run_inference(self, url: str) -> tuple[str, float]:
        """Run canonical 59-feature extraction and XGBoost prediction synchronously."""
        feat_svc = self._get_feature_service()
        pred_svc = self._get_prediction_service()
        df = feat_svc.extract_features(url)
        pred, conf = pred_svc.predict(df)
        return str(pred), float(conf)

    @staticmethod
    def _classify_outcome(
        probe_result: ProbeResult,
        prediction: str,
        confidence: float,
        current_failures: int,
    ) -> tuple[EventType, EventSeverity, str, bool, int]:
        """
        Map probe and ML results into canonical (EventType, EventSeverity, subtype, is_suspension, new_failures).
        """
        # Case 1: SSRF Blocked
        if probe_result.failure_category == ProbeFailureCategory.SSRF_BLOCKED:
            return (
                EventType.SYSTEM_AUDIT,
                EventSeverity.CRITICAL,
                "SSRF_OUTBOUND_PROBE_BLOCKED",
                True,  # is_suspension
                current_failures + 1,
            )

        # Case 2: Probe Network Failure
        if not probe_result.success:
            new_fails = current_failures + 1
            if new_fails >= MAX_CONSECUTIVE_FAILURES:
                return (
                    EventType.TARGET_STATUS_CHANGED,
                    EventSeverity.MEDIUM,
                    "MONITORING_TARGET_SUSPENDED",
                    True,  # is_suspension
                    new_fails,
                )
            return (
                EventType.TARGET_STATUS_CHANGED,
                EventSeverity.LOW,
                "MONITORING_TARGET_UNREACHABLE",
                False,
                new_fails,
            )

        # Case 3: Probe Success -> Reset failure counter to 0
        new_fails = 0

        # Sub-case: Malicious ML (>= 0.85)
        if prediction.upper() == "MALICIOUS" and confidence >= 0.85:
            return (
                EventType.HIGH_RISK_ENRICHMENT,
                EventSeverity.CRITICAL,
                "MONITORING_THREAT_MALICIOUS",
                False,
                new_fails,
            )

        # Sub-case: Suspicious ML (0.60 <= conf < 0.85)
        if prediction.upper() == "MALICIOUS" and 0.60 <= confidence < 0.85:
            return (
                EventType.HIGH_RISK_ENRICHMENT,
                EventSeverity.HIGH,
                "MONITORING_THREAT_SUSPICIOUS",
                False,
                new_fails,
            )

        # Sub-case: Zero-day anomaly hypothesis
        if prediction.upper() in ("ZERO_DAY", "ZERO-DAY"):
            return (
                EventType.ZERO_DAY_DETECTED,
                EventSeverity.CRITICAL,
                "MONITORING_ZERO_DAY_HYPOTHESIS",
                False,
                new_fails,
            )

        # Sub-case: Degraded inference
        if prediction.upper() == "UNKNOWN":
            return (
                EventType.SYSTEM_AUDIT,
                EventSeverity.LOW,
                "MONITORING_INFERENCE_DEGRADED",
                False,
                new_fails,
            )

        # Sub-case: Routine benign
        return (
            EventType.SCAN_COMPLETED,
            EventSeverity.INFO,
            "MONITORING_ROUTINE_BENIGN",
            False,
            new_fails,
        )


# ── Bounded Worker Pool with Per-User Fairness ────────────────────────────────

class MonitoringWorkerPool:
    """
    Manages bounded asynchronous worker execution with deterministic per-user fairness.
    """

    def __init__(
        self,
        global_max_workers: int = GLOBAL_MAX_WORKERS,
        max_user_workers: int = MAX_USER_WORKERS,
        worker: MonitoringWorker | None = None,
    ) -> None:
        self.global_max_workers = global_max_workers
        self.max_user_workers = max_user_workers
        self.worker = worker or MonitoringWorker()

        self._global_semaphore = asyncio.Semaphore(global_max_workers)
        self._user_semaphores: dict[int, asyncio.Semaphore] = {}
        self._active_tasks: set[asyncio.Task] = set()

    def _get_user_semaphore(self, user_id: int) -> asyncio.Semaphore:
        if user_id not in self._user_semaphores:
            self._user_semaphores[user_id] = asyncio.Semaphore(self.max_user_workers)
        return self._user_semaphores[user_id]

    async def submit_target(self, target: ClaimedTarget) -> asyncio.Task | None:
        """
        Dispatch a claimed target to the worker pool under global and user semaphores.
        """
        async def _run():
            async with self._global_semaphore, self._get_user_semaphore(target.user_id):
                return await self.worker.execute_target(target)

        task = asyncio.create_task(_run())
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
        return task

    async def shutdown(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully cancel and drain all active worker tasks."""
        if not self._active_tasks:
            return

        for t in self._active_tasks:
            t.cancel()

        _, pending = await asyncio.wait(self._active_tasks, timeout=timeout_seconds)
        if pending:
            logger.warning("[WORKER_POOL] %d worker tasks forced closed on shutdown", len(pending))
        self._active_tasks.clear()


# ── Singleton Instances ───────────────────────────────────────────────────────
monitoring_worker = MonitoringWorker()
monitoring_worker_pool = MonitoringWorkerPool(worker=monitoring_worker)
