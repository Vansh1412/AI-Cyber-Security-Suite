"""
backend/services/monitoring_engine.py
─────────────────────────────────────
Sprint 5 Phase 5B: Monitoring Engine Service.

Coordinates:
  - Distributed scheduler leadership election and periodic lease renewal
  - Autonomous target claiming loop (when leading)
  - Worker dispatching via bounded MonitoringWorkerPool
  - Graceful lifecycle management with clean task draining and leadership release
  - Environment feature-flag gating (ENABLE_MONITORING_ENGINE)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Callable

from sqlalchemy.orm import Session

from backend.database.session import engine
from backend.services.monitoring_worker import (
    GLOBAL_MAX_WORKERS,
    MAX_USER_WORKERS,
    MonitoringWorkerPool,
)
from backend.services.scheduler_service import (
    SchedulerService,
    scheduler_service,
)
from src.utils.logger import logger


def is_monitoring_engine_enabled() -> bool:
    """Return True if autonomous background monitoring is enabled via environment."""
    return os.getenv("ENABLE_MONITORING_ENGINE", "false").strip().lower() in (
        "true",
        "1",
        "yes",
        "on",
    )


class MonitoringEngine:
    """
    Background orchestrator bridging SchedulerService and MonitoringWorkerPool.
    """

    def __init__(
        self,
        scheduler: SchedulerService | None = None,
        worker_pool: MonitoringWorkerPool | None = None,
        session_factory: Callable[[], Session] | None = None,
        poll_interval_seconds: float = 5.0,
    ) -> None:
        self.scheduler = scheduler or scheduler_service
        self.worker_pool = worker_pool or MonitoringWorkerPool(
            global_max_workers=GLOBAL_MAX_WORKERS,
            max_user_workers=MAX_USER_WORKERS,
        )
        self._session_factory = session_factory or (lambda: Session(bind=engine.sync_engine))
        self.poll_interval_seconds = poll_interval_seconds

        self._is_leader: bool = False
        self._current_epoch: int = 0
        self._loop_task: asyncio.Task | None = None
        self._stopping: bool = False
        self._force_enabled: bool = False

    @property
    def is_leader(self) -> bool:
        return self._is_leader

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    @property
    def is_running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

    async def start(self, force: bool = False) -> bool:
        """
        Start the background monitoring loop if enabled.
        Returns True if engine loop was started, False if disabled.
        """
        if self.is_running:
            logger.warning("[MONITORING_ENGINE] Engine already running.")
            return True

        self._force_enabled = force
        if not (self._force_enabled or is_monitoring_engine_enabled()):
            logger.info("[MONITORING_ENGINE] Background engine disabled by feature flag.")
            return False

        self._stopping = False
        self._loop_task = asyncio.create_task(self._run_loop())
        logger.info(
            "[MONITORING_ENGINE] Started background monitoring loop (poll_interval=%.1fs)",
            self.poll_interval_seconds,
        )
        return True

    async def stop(self, timeout_seconds: float = 5.0) -> None:
        """Gracefully stop the loop, cancel workers, and release leadership."""
        if not self.is_running and not self._stopping:
            return

        logger.info("[MONITORING_ENGINE] Shutting down monitoring engine...")
        self._stopping = True

        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._loop_task
            self._loop_task = None

        # Drain and shutdown worker pool
        await self.worker_pool.shutdown(timeout_seconds=timeout_seconds)

        # Release scheduler leadership if held
        if self._is_leader:
            try:
                sess = self._session_factory()
                try:
                    self.scheduler.release_leadership(sess)
                finally:
                    sess.close()
            except Exception as exc:
                logger.error("[MONITORING_ENGINE] Error releasing leadership during shutdown: %s", exc)
            finally:
                self._is_leader = False
                self._current_epoch = 0

        logger.info("[MONITORING_ENGINE] Shutdown complete.")

    async def _run_loop(self) -> None:
        """Main engine coordination loop."""
        logger.info("[MONITORING_ENGINE] Entering orchestrator loop.")
        while not self._stopping:
            try:
                await self._cycle_step()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[MONITORING_ENGINE] Unexpected error in loop: %s", exc, exc_info=True)

            try:
                await asyncio.sleep(self.poll_interval_seconds)
            except asyncio.CancelledError:
                break

    async def _cycle_step(self) -> None:
        """Perform a single election check and (if leader) target claim batch."""
        # Step 1: Election or Lease Renewal
        sess = self._session_factory()
        try:
            if not self._is_leader:
                state = self.scheduler.attempt_election(sess)
                if state.is_leader:
                    self._is_leader = True
                    self._current_epoch = state.epoch
                    logger.info(
                        "[MONITORING_ENGINE] Promoted to leader for epoch %d",
                        self._current_epoch,
                    )
            else:
                renewed = self.scheduler.renew_lease(sess, self._current_epoch)
                if not renewed:
                    logger.warning("[MONITORING_ENGINE] Lease lost; demoted to follower.")
                    self._is_leader = False
                    self._current_epoch = 0
        except Exception as exc:
            logger.error("[MONITORING_ENGINE] Election/renewal error: %s", exc)
        finally:
            sess.close()

        if not self._is_leader or self._stopping:
            return

        # Step 2: Claim targets and dispatch to worker pool
        claimed_targets = []
        sess = self._session_factory()
        try:
            claimed_targets = self.scheduler.claim_targets(
                sess,
                epoch=self._current_epoch,
            )
        except Exception as exc:
            logger.error("[MONITORING_ENGINE] Claim targets error: %s", exc)
        finally:
            sess.close()

        if claimed_targets:
            logger.info("[MONITORING_ENGINE] Claimed %d targets for execution.", len(claimed_targets))
            for target in claimed_targets:
                if self._stopping:
                    break
                await self.worker_pool.submit_target(target)


monitoring_engine = MonitoringEngine()
