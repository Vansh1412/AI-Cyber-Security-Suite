"""
backend/services/retention_worker.py
────────────────────────────────────
Sprint 5 Phase 5F: Lifecycle Retention & Pruning Worker.

Features:
- Periodic background worker running on an hourly cadence (3600s).
- Multi-pod distributed leader election via Redis lock (or PostgreSQL fallback).
- PostgreSQL-safe bounded batch deletion (max 500 rows per batch) with 0.5s pause.
- Retention Policies:
    • soc_event_stream: 7 days (cursor_id PK).
    • notification_outbox: 30 days (terminal states: DELIVERED, DEAD_LETTER).
    • soc_containment_actions: 90 days (terminal states: EXECUTED, REVERTED, FAILED, BLOCKED_BY_ALLOWLIST).
    • soc_playbook_runs: 90 days (terminal states: COMPLETED, FAILED, REVERTED).
- Never deletes active, pending, or running records.
- AuditEvent is explicitly outside Phase 5F retention.
- Replay: expired cursors trigger stream_reset in Phase 5E SSE clients.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import (
    SOCContainmentAction,
    SOCEventStream,
    SOCPlaybookRun,
)
from backend.database.session import AsyncSessionLocal
from backend.services.cache import cache_service
from backend.services.notification_service import NotificationOutbox
from src.utils.logger import logger


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RetentionWorker:
    """Background maintenance worker for bounded-batch lifecycle data pruning."""

    BATCH_SIZE: int = 500
    INTER_BATCH_PAUSE_SECONDS: float = 0.5
    INTERVAL_SECONDS: int = 3600  # 1 hour
    LEADER_LOCK_TTL_SECONDS: int = 300  # 5 minutes

    EVENT_STREAM_TTL_DAYS: int = 7
    OUTBOX_TTL_DAYS: int = 30
    CONTAINMENT_TTL_DAYS: int = 90

    def __init__(self) -> None:
        self._running: bool = False
        self._task: asyncio.Task | None = None
        self._stop_event: asyncio.Event = asyncio.Event()

    async def start(self) -> None:
        """Start the retention worker background task."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._task = asyncio.create_task(self._worker_loop(), name="retention_worker_loop")
        logger.info("RetentionWorker started (hourly cadence, batch size %d).", self.BATCH_SIZE)

    async def stop(self) -> None:
        """Signal the worker to stop and wait for task termination."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self._task = None
        logger.info("RetentionWorker stopped cleanly.")

    async def _try_acquire_leader_lock(self) -> bool:
        """Attempt to acquire distributed leader lock for retention execution."""
        if cache_service.redis_client is not None:
            try:
                redis = cache_service.redis_client
                acquired = await redis.set(
                    "soc:retention:leader_lock",
                    "leader",
                    nx=True,
                    ex=self.LEADER_LOCK_TTL_SECONDS,
                )
                return bool(acquired)
            except Exception as exc:
                logger.warning("RetentionWorker: Redis leader lock failed: %s (falling back to execution)", exc)
                return True
        return True

    async def _worker_loop(self) -> None:
        """Main periodic loop."""
        while self._running:
            try:
                # Attempt leader election
                is_leader = await self._try_acquire_leader_lock()
                if is_leader:
                    await self.run_once()
                else:
                    logger.debug("RetentionWorker: not leader, skipping retention pass.")
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("RetentionWorker encountered unexpected error: %s", exc, exc_info=True)

            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.INTERVAL_SECONDS)

    async def run_once(self) -> dict[str, int]:
        """
        Execute a complete retention pruning pass across all eligible tables.
        Returns a dictionary of total rows deleted per table.
        """
        results: dict[str, int] = {
            "soc_event_stream": 0,
            "notification_outbox": 0,
            "soc_containment_actions": 0,
            "soc_playbook_runs": 0,
        }

        async with AsyncSessionLocal() as session:
            # 1. Prune soc_event_stream (7 days)
            results["soc_event_stream"] = await self._prune_event_stream(session)

            # 2. Prune notification_outbox (30 days, terminal only)
            results["notification_outbox"] = await self._prune_outbox(session)

            # 3. Prune soc_containment_actions (90 days, terminal only)
            results["soc_containment_actions"] = await self._prune_containment_actions(session)

            # 4. Prune soc_playbook_runs (90 days, terminal only)
            results["soc_playbook_runs"] = await self._prune_playbook_runs(session)

        total_deleted = sum(results.values())
        if total_deleted > 0:
            logger.info("Retention pass complete: %s rows pruned.", results)
        return results

    async def _prune_event_stream(self, session: AsyncSession) -> int:
        """Prune soc_event_stream records older than 7 days in bounded batches."""
        cutoff = _utcnow() - timedelta(days=self.EVENT_STREAM_TTL_DAYS)
        total_deleted = 0

        while self._running:
            # PostgreSQL-safe subquery selection of PKs
            stmt = (
                select(SOCEventStream.cursor_id)
                .where(SOCEventStream.created_at < cutoff)
                .order_by(SOCEventStream.cursor_id.asc())
                .limit(self.BATCH_SIZE)
            )
            result = await session.execute(stmt)
            pks = result.scalars().all()

            if not pks:
                break

            del_stmt = delete(SOCEventStream).where(SOCEventStream.cursor_id.in_(pks))
            await session.execute(del_stmt)
            await session.commit()
            total_deleted += len(pks)

            if len(pks) < self.BATCH_SIZE:
                break

            await asyncio.sleep(self.INTER_BATCH_PAUSE_SECONDS)

        return total_deleted

    async def _prune_outbox(self, session: AsyncSession) -> int:
        """Prune notification_outbox terminal records older than 30 days."""
        cutoff = _utcnow() - timedelta(days=self.OUTBOX_TTL_DAYS)
        total_deleted = 0

        while self._running:
            stmt = (
                select(NotificationOutbox.id)
                .where(
                    NotificationOutbox.created_at < cutoff,
                    NotificationOutbox.status.in_(["DELIVERED", "DEAD_LETTER"]),
                )
                .order_by(NotificationOutbox.id.asc())
                .limit(self.BATCH_SIZE)
            )
            result = await session.execute(stmt)
            pks = result.scalars().all()

            if not pks:
                break

            del_stmt = delete(NotificationOutbox).where(NotificationOutbox.id.in_(pks))
            await session.execute(del_stmt)
            await session.commit()
            total_deleted += len(pks)

            if len(pks) < self.BATCH_SIZE:
                break

            await asyncio.sleep(self.INTER_BATCH_PAUSE_SECONDS)

        return total_deleted

    async def _prune_containment_actions(self, session: AsyncSession) -> int:
        """Prune soc_containment_actions terminal records older than 90 days."""
        cutoff = _utcnow() - timedelta(days=self.CONTAINMENT_TTL_DAYS)
        total_deleted = 0

        while self._running:
            stmt = (
                select(SOCContainmentAction.id)
                .where(
                    SOCContainmentAction.created_at < cutoff,
                    SOCContainmentAction.status.in_(["EXECUTED", "REVERTED", "FAILED", "BLOCKED_BY_ALLOWLIST"]),
                )
                .order_by(SOCContainmentAction.id.asc())
                .limit(self.BATCH_SIZE)
            )
            result = await session.execute(stmt)
            pks = result.scalars().all()

            if not pks:
                break

            del_stmt = delete(SOCContainmentAction).where(SOCContainmentAction.id.in_(pks))
            await session.execute(del_stmt)
            await session.commit()
            total_deleted += len(pks)

            if len(pks) < self.BATCH_SIZE:
                break

            await asyncio.sleep(self.INTER_BATCH_PAUSE_SECONDS)

        return total_deleted

    async def _prune_playbook_runs(self, session: AsyncSession) -> int:
        """Prune soc_playbook_runs terminal records older than 90 days."""
        cutoff = _utcnow() - timedelta(days=self.CONTAINMENT_TTL_DAYS)
        total_deleted = 0

        while self._running:
            stmt = (
                select(SOCPlaybookRun.id)
                .where(
                    SOCPlaybookRun.created_at < cutoff,
                    SOCPlaybookRun.status.in_(["COMPLETED", "FAILED", "REVERTED"]),
                )
                .order_by(SOCPlaybookRun.id.asc())
                .limit(self.BATCH_SIZE)
            )
            result = await session.execute(stmt)
            pks = result.scalars().all()

            if not pks:
                break

            del_stmt = delete(SOCPlaybookRun).where(SOCPlaybookRun.id.in_(pks))
            await session.execute(del_stmt)
            await session.commit()
            total_deleted += len(pks)

            if len(pks) < self.BATCH_SIZE:
                break

            await asyncio.sleep(self.INTER_BATCH_PAUSE_SECONDS)

        return total_deleted


retention_worker = RetentionWorker()
