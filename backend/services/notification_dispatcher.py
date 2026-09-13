"""
backend/services/notification_dispatcher.py
───────────────────────────────────────────
Sprint 5 Phase 5D: Background Notification Dispatcher, SSRF-Safe Pinned HTTP Egress,
At-Least-Once Delivery, Jittered Exponential Backoff, and Atomic Circuit Breaker.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import random
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import httpcore
import httpx
from sqlalchemy import and_, or_, select, text
from sqlalchemy.orm import Session

from backend.core.security_network import (
    SSRFSecurityError,
    resolve_and_validate_host,
    validate_target_url,
)
from backend.database.models import AuditEvent, Notification, NotificationPreference
from backend.database.session import engine
from backend.services.notification_service import (
    NotificationOutbox,
    compute_hmac_signature,
    decrypt_webhook_secret,
)
from src.utils.logger import logger


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


# ── Pinned Transport Layer (Anti-DNS Rebinding / SSRF) ────────────────────────

class WebhookPinnedIPBackend(httpcore.AsyncNetworkBackend):
    """
    Decouples TCP connection destination from TLS certificate validation & Host header.
    Forces connection directly to pinned_ip, eliminating TOCTOU / DNS rebinding.
    """

    def __init__(self, pinned_ip: str):
        self._default = httpcore.AnyIOBackend()
        self._pinned_ip = pinned_ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._default.connect_tcp(
            host=self._pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs):
        return await self._default.connect_unix_socket(*args, **kwargs)

    async def sleep(self, seconds: float):
        await self._default.sleep(seconds)


class WebhookPinnedTransport(httpx.AsyncHTTPTransport):
    """AsyncHTTPTransport injecting WebhookPinnedIPBackend into connection pool."""

    def __init__(self, pinned_ip: str, **kwargs):
        super().__init__(**kwargs)
        self._pool._network_backend = WebhookPinnedIPBackend(pinned_ip)


# ── Concurrency Synchronization for SQLite Test Harness ───────────────────────
_outbox_claim_lock = asyncio.Lock()


# ── Notification Dispatcher Engine ────────────────────────────────────────────

class NotificationDispatcher:
    """
    Background worker engine claiming pending outbox jobs and dispatching webhooks
    with fail-closed SSRF protection, HMAC authentication, and atomic circuit breakers.
    """

    MAX_ATTEMPTS: int = 3
    LEASE_EXPIRY_SECONDS: int = 60
    DISPATCH_TIMEOUT_S: float = 3.0
    MAX_RESPONSE_BYTES: int = 16384  # 16 KB

    def __init__(
        self,
        pod_id: str | None = None,
        session_factory: Callable[[], Session] | None = None,
    ):
        self.pod_id = pod_id or f"dispatcher-{uuid.uuid4().hex[:8]}"
        self._session_factory = session_factory or (lambda: Session(bind=engine.sync_engine))
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start background polling task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("[DISPATCHER] NotificationDispatcher started (pod: %s)", self.pod_id)

    async def stop(self) -> None:
        """Stop background polling task."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        logger.info("[DISPATCHER] NotificationDispatcher stopped")

    async def _poll_loop(self) -> None:
        """Continuous polling cycle."""
        while self._running:
            try:
                await self.tick()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[DISPATCHER] Unexpected error in polling tick: %s", exc)
            await asyncio.sleep(1.0)

    async def tick(self, batch_size: int = 10) -> int:
        """Execute a single claiming and delivery cycle. Returns count of processed jobs."""
        claimed = self._claim_jobs_sync(batch_size=batch_size)
        if not claimed:
            return 0

        for job in claimed:
            try:
                await self._dispatch_job(job)
            except Exception as exc:
                logger.error("[DISPATCHER] Failed to dispatch job %s: %s", job.outbox_uuid, exc)

        return len(claimed)

    # ── Job Claiming Protocol ─────────────────────────────────────────────────

    def _claim_jobs_sync(self, batch_size: int = 10) -> list[NotificationOutbox]:
        """
        Claim up to batch_size eligible outbox records atomically using
        SELECT ... FOR UPDATE SKIP LOCKED on PostgreSQL, or serialized transaction on SQLite.
        """
        now = _utcnow()
        stale_threshold = now - timedelta(seconds=self.LEASE_EXPIRY_SECONDS)

        with self._session_factory() as sess:
            dialect = sess.bind.dialect.name if sess.bind else "sqlite"

            if dialect == "postgresql":
                stmt = (
                    select(NotificationOutbox)
                    .where(
                        or_(
                            NotificationOutbox.status == "PENDING",
                            and_(
                                NotificationOutbox.status == "PROCESSING",
                                NotificationOutbox.locked_at < stale_threshold,
                            ),
                        ),
                        NotificationOutbox.next_attempt_at <= now,
                    )
                    .order_by(NotificationOutbox.next_attempt_at.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
                jobs = list(sess.scalars(stmt).all())
                for job in jobs:
                    job.status = "PROCESSING"
                    job.locked_at = now
                    job.locked_by = self.pod_id
                sess.commit()
                return jobs

            # SQLite test-harness emulation:
            # Reclaim stale processing jobs or claim pending jobs
            stmt = (
                select(NotificationOutbox)
                .where(
                    or_(
                        NotificationOutbox.status == "PENDING",
                        and_(
                            NotificationOutbox.status == "PROCESSING",
                            NotificationOutbox.locked_at < stale_threshold,
                        ),
                    ),
                    NotificationOutbox.next_attempt_at <= now,
                )
                .order_by(NotificationOutbox.next_attempt_at.asc())
                .limit(batch_size)
            )
            jobs = list(sess.scalars(stmt).all())
            for job in jobs:
                job.status = "PROCESSING"
                job.locked_at = now
                job.locked_by = self.pod_id
            sess.commit()
            return jobs

    # ── Webhook Delivery Execution (Outside DB Transaction) ───────────────────

    async def _dispatch_job(self, job: NotificationOutbox) -> None:
        """
        Execute webhook HTTP POST outside DB transaction, then atomically write back result.
        """
        t0 = time.time()

        # 1. Fetch user preference & secret
        with self._session_factory() as sess:
            pref = sess.query(NotificationPreference).filter(
                NotificationPreference.user_id == job.user_id
            ).first()
            if not pref:
                self._record_job_terminal_failure(job.id, "User preference missing.")
                return

            if not pref.webhook_enabled or getattr(pref, "circuit_broken", False):
                self._record_job_terminal_failure(job.id, "Webhook disabled or circuit broken.")
                return

            stored_secret = getattr(pref, "encrypted_webhook_secret", None) or pref.webhook_secret
            if not stored_secret:
                self._record_job_terminal_failure(job.id, "Webhook secret not configured.")
                return

            try:
                secret = (
                    decrypt_webhook_secret(stored_secret)
                    if stored_secret.startswith("v1$")
                    else stored_secret
                )
            except Exception as exc:
                self._record_job_terminal_failure(
                    job.id, f"Secret decryption failure: {exc}", is_security=True
                )
                return

        # 2. SSRF Pre-flight & DNS Pinning Validation
        try:
            scheme, hostname, port, path_and_query = validate_target_url(job.destination_url)
            validated_ips = await resolve_and_validate_host(hostname)
        except SSRFSecurityError as exc:
            logger.warning("[DISPATCHER] SSRF blocked for destination '%s': %s", job.destination_url, exc)
            self._record_job_terminal_failure(job.id, f"SSRF security violation: {exc}", is_ssrf=True)
            return
        except Exception as exc:
            # DNS resolution failure
            self._record_job_retry_or_fail(job.id, f"DNS resolution failed: {exc}", job.attempt_count)
            return

        pinned_ip = validated_ips[0]
        host_header = hostname if port in (80, 443) else f"{hostname}:{port}"

        # 3. Canonical Payload Serialization & HMAC Signature
        payload_bytes = json.dumps(job.payload_json, separators=(",", ":")).encode("utf-8")
        current_epoch = int(time.time())
        signature_hex = compute_hmac_signature(secret, current_epoch, payload_bytes)

        delivery_id = _uuid_str()
        alert_uuid = job.payload_json.get("alert_uuid", "")
        event_name = job.payload_json.get("event", "ALERT")
        occ_count = job.payload_json.get("occurrence_count", 1)
        event_id = hashlib.sha256(f"{alert_uuid}:WEBHOOK:{event_name}:{occ_count}".encode()).hexdigest()

        headers = {
            "Host": host_header,
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "AI-Cyber-Security-Suite-Webhook/1.0",
            "X-SOC-Delivery-ID": delivery_id,
            "X-SOC-Event-ID": event_id,
            "X-SOC-Timestamp": str(current_epoch),
            "X-SOC-Signature-256": f"t={current_epoch},v1={signature_hex}",
            "Connection": "close",
        }

        transport = WebhookPinnedTransport(pinned_ip=pinned_ip)
        timeout = httpx.Timeout(self.DISPATCH_TIMEOUT_S)

        # 4. Outbound Request Execution
        try:
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,  # CRITICAL: redirects strictly forbidden
                timeout=timeout,
            ) as client:
                resp = await client.post(
                    job.destination_url,
                    content=payload_bytes,
                    headers=headers,
                )
                status_code = resp.status_code
                latency_ms = round((time.time() - t0) * 1000, 2)

                # Classification
                if 200 <= status_code < 300:
                    # Success
                    self._record_job_success(job.id, job.user_id, latency_ms)
                elif 300 <= status_code < 400:
                    # Redirect = security failure
                    self._record_job_terminal_failure(
                        job.id, f"Permanent failure: HTTP redirect ({status_code}) prohibited.", is_client=True
                    )
                elif 400 <= status_code < 500:
                    # Permanent client error
                    self._record_job_terminal_failure(
                        job.id, f"Client error HTTP {status_code}.", is_client=True
                    )
                else:
                    # 5xx = Transient server error
                    self._record_job_retry_or_fail(
                        job.id, f"Server error HTTP {status_code}.", job.attempt_count
                    )

        except httpx.TimeoutException as exc:
            self._record_job_retry_or_fail(job.id, f"Connection timeout: {exc}", job.attempt_count)
        except Exception as exc:
            self._record_job_retry_or_fail(job.id, f"Network transport error: {exc}", job.attempt_count)

    # ── Status Writeback & Circuit Breaker Handlers ────────────────────────────

    def _record_job_success(self, job_id: int, user_id: int, latency_ms: float) -> None:
        """Mark job DELIVERED and atomically reset circuit breaker failure counter."""
        now = _utcnow()
        with self._session_factory() as sess:
            # 1. Update job
            job = sess.get(NotificationOutbox, job_id)
            if job:
                job.status = "DELIVERED"
                job.delivered_at = now
                job.last_error = None
                job.locked_at = None
                job.locked_by = None

            # 2. Atomic counter reset (only if circuit is NOT already broken)
            sess.execute(
                text(
                    "UPDATE notification_preferences "
                    "SET consecutive_failures = 0 "
                    "WHERE user_id = :user_id AND NOT circuit_broken"
                ),
                {"user_id": user_id},
            )
            sess.commit()
            logger.info("[DISPATCHER] Webhook job %d DELIVERED in %.1f ms", job_id, latency_ms)

    def _record_job_terminal_failure(
        self,
        job_id: int,
        error_msg: str,
        is_ssrf: bool = False,
        is_client: bool = False,
        is_security: bool = False,
    ) -> None:
        """Mark job permanently FAILED and trigger atomic failure increment."""
        with self._session_factory() as sess:
            job = sess.get(NotificationOutbox, job_id)
            user_id = job.user_id if job else None
            if job:
                job.status = "FAILED"
                job.last_error = error_msg[:512]
                job.locked_at = None
                job.locked_by = None

            if user_id:
                self._increment_circuit_breaker(sess, user_id, is_ssrf=is_ssrf)

            sess.commit()
            logger.warning("[DISPATCHER] Webhook job %d permanently FAILED: %s", job_id, error_msg)

    def _record_job_retry_or_fail(self, job_id: int, error_msg: str, current_attempt: int) -> None:
        """Schedule retry with exponential backoff and jitter, or mark FAILED after 3 attempts."""
        now = _utcnow()
        new_attempt = current_attempt + 1

        with self._session_factory() as sess:
            job = sess.get(NotificationOutbox, job_id)
            if not job:
                return

            if new_attempt >= self.MAX_ATTEMPTS:
                # Max attempts exhausted
                job.status = "FAILED"
                job.attempt_count = new_attempt
                job.last_error = f"Max attempts (3) exhausted: {error_msg}"[:512]
                job.locked_at = None
                job.locked_by = None
                self._increment_circuit_breaker(sess, job.user_id)
                sess.commit()
                logger.warning("[DISPATCHER] Webhook job %d FAILED after 3 attempts: %s", job_id, error_msg)
            else:
                # Schedule retry
                backoff = min(60.0, 5.0 * (2 ** (new_attempt - 1))) + random.uniform(0.5, 2.0)
                job.status = "PENDING"
                job.attempt_count = new_attempt
                job.next_attempt_at = now + timedelta(seconds=backoff)
                job.last_error = error_msg[:512]
                job.locked_at = None
                job.locked_by = None
                sess.commit()
                logger.info(
                    "[DISPATCHER] Webhook job %d scheduled retry #%d in %.1fs: %s",
                    job_id,
                    new_attempt,
                    backoff,
                    error_msg,
                )

    def _increment_circuit_breaker(self, sess: Session, user_id: int, is_ssrf: bool = False) -> None:
        """
        Atomically increment consecutive_failures and trip circuit breaker at 5 failures.
        Emits In-App notification and AuditEvent on the exact transition cycle.
        """
        now = _utcnow()
        dialect = sess.bind.dialect.name if sess.bind else "sqlite"

        # Atomic SQL update
        sql = text(
            "UPDATE notification_preferences "
            "SET "
            "    consecutive_failures = consecutive_failures + 1, "
            "    circuit_broken = CASE WHEN consecutive_failures + 1 >= 5 THEN 1 ELSE circuit_broken END, "
            "    circuit_broken_at = CASE WHEN consecutive_failures + 1 >= 5 AND NOT circuit_broken THEN :now ELSE circuit_broken_at END, "
            "    webhook_enabled = CASE WHEN consecutive_failures + 1 >= 5 THEN 0 ELSE webhook_enabled END "
            "WHERE user_id = :user_id "
        )
        if dialect == "postgresql":
            sql = text(
                "UPDATE notification_preferences "
                "SET "
                "    consecutive_failures = consecutive_failures + 1, "
                "    circuit_broken = CASE WHEN consecutive_failures + 1 >= 5 THEN TRUE ELSE circuit_broken END, "
                "    circuit_broken_at = CASE WHEN consecutive_failures + 1 >= 5 AND NOT circuit_broken THEN NOW() ELSE circuit_broken_at END, "
                "    webhook_enabled = CASE WHEN consecutive_failures + 1 >= 5 THEN FALSE ELSE webhook_enabled END "
                "WHERE user_id = :user_id "
                "RETURNING consecutive_failures, circuit_broken, (consecutive_failures >= 5 AND NOT circuit_broken) AS just_tripped"
            )

        sess.execute(sql, {"user_id": user_id, "now": now})

        # Check if circuit just tripped
        pref = sess.query(NotificationPreference).filter(NotificationPreference.user_id == user_id).first()
        if pref and pref.consecutive_failures >= 5 and pref.circuit_broken:
            # Emit Warning Notification and AuditEvent EXACTLY ONCE per trip
            trip_time = pref.circuit_broken_at or now
            already_recorded = sess.query(AuditEvent).filter(
                AuditEvent.actor_user_id == user_id,
                AuditEvent.action == "WEBHOOK_CIRCUIT_BROKEN",
                AuditEvent.target_resource == "notification_preferences",
                AuditEvent.created_at >= trip_time,
            ).first()

            if not already_recorded:
                notif = Notification(
                    notification_uuid=_uuid_str(),
                    user_id=user_id,
                    title="[WARNING] Webhook Delivery Disabled",
                    message="Webhook delivery disabled: 5 consecutive delivery failures encountered. Please verify your endpoint and secret.",
                    severity="HIGH",
                    is_read=False,
                    link_url="/notifications/preferences",
                    created_at=trip_time,
                )
                sess.add(notif)

                # Emit AuditEvent
                audit = AuditEvent(
                    action="WEBHOOK_CIRCUIT_BROKEN",
                    actor_user_id=user_id,
                    target_resource="notification_preferences",
                    resource_id=str(pref.id),
                    details={
                        "consecutive_failures": pref.consecutive_failures,
                        "circuit_broken": True,
                        "reason": "5 consecutive delivery failures",
                    },
                    created_at=trip_time,
                )
                sess.add(audit)

        if is_ssrf:
            audit_ssrf = AuditEvent(
                action="WEBHOOK_SSRF_ABORTED",
                actor_user_id=user_id,
                target_resource="notification_outbox",
                resource_id="egress",
                details={"reason": "SSRF blocked on webhook egress"},
                created_at=now,
            )
            sess.add(audit_ssrf)


notification_dispatcher = NotificationDispatcher()
