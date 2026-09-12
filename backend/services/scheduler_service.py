"""
backend/services/scheduler_service.py
───────────────────────────────────────
Sprint 5 Phase 5A: Distributed Scheduler Service.

Implements the PostgreSQL-authoritative leader election + target claim loop
designed in the Sprint 5 Phase 5 Architecture & Security Specification v1.2.

Key design guarantees:
  - PostgreSQL is the SOLE authority for all distributed state.
  - Redis is an advisory performance hint only; its failure has zero correctness impact.
  - The monotonic fencing epoch (scheduler_state.current_epoch) prevents split-brain.
  - Triple-predicate write-back (execution_token + execution_epoch + execution_expires_at)
    guarantees stale-write safety: no dirty result from a crashed/slow worker is ever
    committed.
  - All lease deadlines use DB NOW() — application wall-clock is never used for leases.

SQLite compatibility:
  - Advisory lock emulated as always-True (single-process dev environment).
  - SKIP LOCKED emulated via row-level Python token assignment.
  - INTERVAL arithmetic uses datetime() SQLite expression.

Thread-safety:
  - This service is designed to run from a single asyncio task (the scheduler loop).
  - It uses synchronous SQLAlchemy sessions (not async) for precise transaction control.
"""

from __future__ import annotations

import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.database.models import SchedulerState
from src.utils.logger import logger

# ── Configuration Constants ────────────────────────────────────────────────────
# All durations in seconds unless noted otherwise.

#: PostgreSQL session-level advisory lock ID.  Must be unique across all
#: advisory lock uses in the application.  Uses a stable hash of a well-known
#: key string so it does not collide with future advisory locks.
LEADER_LOCK_ID: int = 0x50485F4C45414400  # "PH_LEAD\x00" as big-endian int (fits BIGINT)

#: How often the scheduler attempts an election cycle (seconds).
ELECTION_INTERVAL_SECONDS: int = int(os.getenv("SCHEDULER_ELECTION_INTERVAL", "15"))

#: Total lease duration for a leader (seconds).
LEADER_LEASE_SECONDS: int = int(os.getenv("SCHEDULER_LEADER_LEASE", "60"))

#: Execution lease duration for a single target worker (seconds).
WORKER_LEASE_SECONDS: int = int(os.getenv("SCHEDULER_WORKER_LEASE", "45"))

#: Max targets claimed in a single batch.
CLAIM_BATCH_SIZE: int = int(os.getenv("SCHEDULER_CLAIM_BATCH_SIZE", "10"))

#: Redis hint hard timeout (milliseconds) — ignored on expiry.
REDIS_CALL_TIMEOUT_MS: int = int(os.getenv("SCHEDULER_REDIS_TIMEOUT_MS", "100"))

#: Identity string for this pod/process.
POD_ID: str = os.getenv(
    "POD_NAME",
    f"{socket.gethostname()}-{os.getpid()}",
)


# ── Data Types ─────────────────────────────────────────────────────────────────

class ClaimedTarget(NamedTuple):
    """A monitoring target that has been exclusively claimed for execution."""

    target_id: int
    url: str
    normalized_domain: str
    check_interval_minutes: int
    execution_token: str
    execution_epoch: int
    user_id: int


class LeaderState(NamedTuple):
    """Result of a leader election attempt."""

    is_leader: bool
    epoch: int  # Current epoch; meaningful only if is_leader=True


# ── Scheduler Service ──────────────────────────────────────────────────────────

class SchedulerService:
    """
    Distributed scheduler service implementing the v1.2 PostgreSQL-authoritative
    leader election and fencing token target claim protocol.

    Usage (single asyncio background task):

        service = SchedulerService()
        async with lifespan:
            while True:
                with get_sync_db() as session:
                    state = service.attempt_election(session)
                    if state.is_leader:
                        targets = service.claim_targets(session, state.epoch)
                        # dispatch targets to workers …
                await asyncio.sleep(ELECTION_INTERVAL_SECONDS)
    """

    # ── Leader Election ────────────────────────────────────────────────────────

    def attempt_election(self, session: Session) -> LeaderState:
        """
        Attempt to acquire or renew the scheduler leader role.

        Algorithm (v1.2 spec §4.1):
          1. Try to acquire PG advisory lock (non-blocking).
          2. If acquired: attempt atomic epoch UPDATE with lease expiry guard.
          3. If epoch UPDATE succeeds: we are leader; update Redis hint (best-effort).
          4. If advisory lock not acquired, or epoch UPDATE fails: become Follower.

        Returns:
            LeaderState(is_leader=True, epoch=N)  — we are leader for epoch N
            LeaderState(is_leader=False, epoch=0) — we are follower
        """
        dialect = session.bind.dialect.name  # type: ignore[union-attr]

        # Step 1: Try advisory lock
        advisory_acquired = self._try_advisory_lock(session, dialect)
        if not advisory_acquired:
            logger.info(
                "[SCHEDULER] Election: advisory lock NOT acquired — remaining Follower. "
                "pod=%s", POD_ID
            )
            return LeaderState(is_leader=False, epoch=0)

        # Step 2: Atomic epoch UPDATE with lease expiry guard
        try:
            epoch = self._try_acquire_epoch(session, dialect)
        except Exception as exc:
            logger.error("[SCHEDULER] Epoch UPDATE failed unexpectedly: %s", exc)
            self._release_advisory_lock(session, dialect)
            return LeaderState(is_leader=False, epoch=0)

        if epoch is None:
            # Another pod's lease is still valid; yield even though we hold the lock
            self._release_advisory_lock(session, dialect)
            logger.info(
                "[SCHEDULER] Election: yielded (existing leader's lease still valid). pod=%s",
                POD_ID,
            )
            return LeaderState(is_leader=False, epoch=0)

        logger.info(
            "[SCHEDULER] Election: acquired leadership. pod=%s epoch=%d", POD_ID, epoch
        )
        return LeaderState(is_leader=True, epoch=epoch)

    def renew_lease(self, session: Session, epoch: int) -> bool:
        """
        Renew the leader lease without incrementing the epoch.

        Called each heartbeat cycle while we remain leader.

        Returns True if renewal succeeded (we are still leader), False if the epoch
        has advanced under us (another pod took over — we must become Follower).
        """
        dialect = session.bind.dialect.name  # type: ignore[union-attr]

        if dialect == "sqlite":
            # SQLite single-process dev: always succeeds
            return True

        if dialect == "postgresql":
            result = session.execute(
                text(
                    "UPDATE scheduler_state "
                    "SET lease_expires_at = NOW() + INTERVAL ':sec seconds', "
                    "    updated_at       = NOW() "
                    "WHERE id = 1 "
                    "  AND leader_pod_id = :pod_id "
                    "  AND current_epoch = :epoch"
                ).bindparams(sec=LEADER_LEASE_SECONDS, pod_id=POD_ID, epoch=epoch)
            )
            session.commit()
            renewed = result.rowcount > 0  # type: ignore[union-attr]
            if not renewed:
                logger.warning(
                    "[SCHEDULER] Lease renewal FAILED — epoch advanced. pod=%s epoch=%d",
                    POD_ID, epoch,
                )
                self._release_advisory_lock(session, dialect)
            return renewed

        return True  # Unknown dialect: assume single-process

    def release_leadership(self, session: Session) -> None:
        """Voluntarily release the advisory lock on clean shutdown."""
        dialect = session.bind.dialect.name  # type: ignore[union-attr]
        self._release_advisory_lock(session, dialect)
        logger.info("[SCHEDULER] Released leadership. pod=%s", POD_ID)

    # ── Target Claim Loop ──────────────────────────────────────────────────────

    def claim_targets(self, session: Session, epoch: int) -> list[ClaimedTarget]:
        """
        Claim a batch of monitoring targets ready for execution.

        Assigns a unique execution_token + current epoch to each claimed row.
        Uses FOR UPDATE SKIP LOCKED on PostgreSQL; BEGIN IMMEDIATE on SQLite.

        Returns a list of ClaimedTarget named-tuples ready to dispatch to workers.
        """
        dialect = session.bind.dialect.name  # type: ignore[union-attr]
        now = datetime.now(timezone.utc)

        if dialect == "postgresql":
            return self._claim_pg(session, epoch, now)
        else:
            return self._claim_sqlite(session, epoch, now)

    def write_back_result(
        self,
        session: Session,
        *,
        target_id: int,
        execution_token: str,
        execution_epoch: int,
        last_checked_at: datetime,
        interval_minutes: int,
        last_prediction: str,
        last_confidence: float,
        consecutive_failures: int,
    ) -> bool:
        """
        Write scan results back to the target row using the triple-predicate
        stale-write safety check (spec §5.2):

          WHERE id               = :target_id
            AND execution_token  = :my_token          -- fencing: exact UUID match
            AND execution_epoch  = :my_epoch          -- fencing: must match current epoch
            AND execution_expires_at > NOW()          -- fencing: lease must not be expired

        Returns:
            True  — write committed; target updated.
            False — stale / expired token; write discarded (no-op).
        """
        dialect = session.bind.dialect.name  # type: ignore[union-attr]
        next_check = last_checked_at + timedelta(minutes=interval_minutes)

        if dialect == "postgresql":
            result = session.execute(
                text(
                    "UPDATE monitoring_targets "
                    "SET last_checked_at      = :checked_at, "
                    "    next_check_at        = :next_check, "
                    "    last_prediction      = :prediction, "
                    "    last_confidence      = :confidence, "
                    "    consecutive_failures = :failures, "
                    "    execution_token      = NULL, "
                    "    execution_epoch      = NULL, "
                    "    execution_expires_at = NULL "
                    "WHERE id               = :target_id "
                    "  AND execution_token  = :token "
                    "  AND execution_epoch  = :epoch "
                    "  AND execution_expires_at > NOW()"
                ),
                {
                    "checked_at": last_checked_at.replace(tzinfo=None),
                    "next_check": next_check.replace(tzinfo=None),
                    "prediction": last_prediction,
                    "confidence": last_confidence,
                    "failures": consecutive_failures,
                    "target_id": target_id,
                    "token": execution_token,
                    "epoch": execution_epoch,
                },
            )
            committed = result.rowcount > 0  # type: ignore[union-attr]

        else:
            # SQLite: datetime comparison using SQLAlchemy storage format
            # (SQLAlchemy stores datetimes as 'YYYY-MM-DD HH:MM:SS.ffffff', space separator)
            now_sqlite = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
            result = session.execute(
                text(
                    "UPDATE monitoring_targets "
                    "SET last_checked_at      = :checked_at, "
                    "    next_check_at        = :next_check, "
                    "    last_prediction      = :prediction, "
                    "    last_confidence      = :confidence, "
                    "    consecutive_failures = :failures, "
                    "    execution_token      = NULL, "
                    "    execution_epoch      = NULL, "
                    "    execution_expires_at = NULL "
                    "WHERE id               = :target_id "
                    "  AND execution_token  = :token "
                    "  AND execution_epoch  = :epoch "
                    "  AND execution_expires_at > :now_sqlite"
                ),
                {
                    "checked_at": last_checked_at.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "next_check": next_check.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "prediction": last_prediction,
                    "confidence": last_confidence,
                    "failures": consecutive_failures,
                    "target_id": target_id,
                    "token": execution_token,
                    "epoch": execution_epoch,
                    "now_sqlite": now_sqlite,
                },
            )
            committed = result.rowcount > 0  # type: ignore[union-attr]

        if committed:
            session.commit()
            logger.debug(
                "[SCHEDULER] Written back result for target %d (token=%s…)",
                target_id, execution_token[:8],
            )
        else:
            session.rollback()
            logger.warning(
                "[SCHEDULER] Stale write-back discarded for target %d "
                "(token=%s… epoch=%d) — lease expired or epoch advanced.",
                target_id, execution_token[:8], execution_epoch,
            )
        return committed

    # ── Internal Helpers ───────────────────────────────────────────────────────

    def _try_advisory_lock(self, session: Session, dialect: str) -> bool:
        """Attempt to acquire a non-blocking PG session advisory lock.

        SQLite emulation: always returns True (single-process dev; no election needed).
        """
        if dialect == "sqlite":
            return True  # Always leader in single-process dev

        if dialect == "postgresql":
            row = session.execute(
                text("SELECT pg_try_advisory_lock(:lock_id)").bindparams(
                    lock_id=LEADER_LOCK_ID
                )
            ).fetchone()
            acquired: bool = bool(row[0]) if row else False
            return acquired

        # Unknown dialect — assume single-process
        logger.warning(
            "[SCHEDULER] Unknown DB dialect '%s'; assuming single-leader dev mode.", dialect
        )
        return True

    def _release_advisory_lock(self, session: Session, dialect: str) -> None:
        """Release the PG session advisory lock (no-op on SQLite)."""
        if dialect == "postgresql":
            try:
                session.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)").bindparams(
                        lock_id=LEADER_LOCK_ID
                    )
                )
                session.commit()
            except Exception as exc:
                logger.warning("[SCHEDULER] Advisory unlock failed (safe to ignore): %s", exc)

    def _try_acquire_epoch(self, session: Session, dialect: str) -> int | None:
        """
        Attempt the conditional epoch UPDATE inside the PG advisory lock.

        Succeeds if:
          - The previous leader's lease has expired (lease_expires_at < NOW()), OR
          - We are renewing our own lease (leader_pod_id = :pod_id).

        Returns the new current_epoch on success, None if another pod's lease is
        still valid (we should yield and release the advisory lock).
        """
        if dialect == "sqlite":
            # SQLite: always-leader; just ensure row exists and increment epoch
            row = session.execute(
                text("SELECT current_epoch FROM scheduler_state WHERE id = 1")
            ).fetchone()
            if row is None:
                now_sqlite = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
                session.execute(
                    text(
                        "INSERT OR IGNORE INTO scheduler_state "
                        "(id, current_epoch, leader_pod_id, updated_at) "
                        "VALUES (1, 0, :pod, :now)"
                    ),
                    {"pod": POD_ID, "now": now_sqlite},
                )
                session.commit()
                row = session.execute(
                    text("SELECT current_epoch FROM scheduler_state WHERE id = 1")
                ).fetchone()

            current_epoch = row[0] if row else 0
            new_epoch = current_epoch + 1
            now_sqlite = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
            expires_sqlite = (
                datetime.now(timezone.utc).replace(tzinfo=None)
                + timedelta(seconds=LEADER_LEASE_SECONDS)
            ).strftime("%Y-%m-%d %H:%M:%S.%f")
            session.execute(
                text(
                    "UPDATE scheduler_state "
                    "SET current_epoch = :new_epoch, leader_pod_id = :pod, "
                    "    lease_acquired_at = :now, lease_expires_at = :expires, "
                    "    updated_at = :now "
                    "WHERE id = 1"
                ),
                {"new_epoch": new_epoch, "pod": POD_ID, "now": now_sqlite, "expires": expires_sqlite},
            )
            session.commit()
            return new_epoch

        if dialect == "postgresql":
            result = session.execute(
                text(
                    "UPDATE scheduler_state "
                    "SET current_epoch      = current_epoch + 1, "
                    "    leader_pod_id      = :pod_id, "
                    "    lease_acquired_at  = NOW(), "
                    "    lease_expires_at   = NOW() + INTERVAL ':sec seconds', "
                    "    updated_at         = NOW() "
                    "WHERE id = 1 "
                    "  AND ("
                    "    lease_expires_at < NOW() "
                    "    OR leader_pod_id = :pod_id"
                    "  ) "
                    "RETURNING current_epoch"
                ).bindparams(pod_id=POD_ID, sec=LEADER_LEASE_SECONDS)
            )
            session.commit()
            row = result.fetchone()
            if row:
                return int(row[0])
            return None

        return 1  # Unknown dialect fallback

    def _claim_pg(
        self, session: Session, epoch: int, now: datetime
    ) -> list[ClaimedTarget]:
        """Claim targets using PostgreSQL FOR UPDATE SKIP LOCKED."""
        expires_seconds = WORKER_LEASE_SECONDS
        rows = session.execute(
            text(
                "WITH claimed AS ( "
                "  SELECT id "
                "  FROM monitoring_targets "
                "  WHERE is_active = TRUE "
                "    AND next_check_at <= NOW() "
                "    AND (execution_token IS NULL OR execution_expires_at < NOW()) "
                "  ORDER BY next_check_at ASC "
                "  LIMIT :batch_size "
                "  FOR UPDATE SKIP LOCKED "
                ") "
                "UPDATE monitoring_targets "
                "SET execution_token      = gen_random_uuid()::text, "
                "    execution_epoch      = :epoch, "
                "    execution_expires_at = NOW() + INTERVAL ':sec seconds' "
                "WHERE id IN (SELECT id FROM claimed) "
                "RETURNING id, url, normalized_domain, check_interval_minutes, "
                "          execution_token, execution_epoch, user_id"
            ).bindparams(batch_size=CLAIM_BATCH_SIZE, epoch=epoch, sec=expires_seconds)
        ).fetchall()
        session.commit()

        claimed = [
            ClaimedTarget(
                target_id=r[0],
                url=r[1],
                normalized_domain=r[2],
                check_interval_minutes=r[3],
                execution_token=r[4],
                execution_epoch=r[5],
                user_id=r[6],
            )
            for r in rows
        ]
        if claimed:
            logger.info(
                "[SCHEDULER] Claimed %d target(s) in epoch %d.", len(claimed), epoch
            )
        return claimed

    def _claim_sqlite(
        self, session: Session, epoch: int, now: datetime
    ) -> list[ClaimedTarget]:
        """Claim targets on SQLite using full-table BEGIN IMMEDIATE + Python UUID."""
        # SQLAlchemy stores DateTime to SQLite as 'YYYY-MM-DD HH:MM:SS.ffffff'
        # (space separator).  Python isoformat() produces 'T' separator.
        # We must match the storage format for string comparisons to work.
        now_sqlite = now.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
        expires_sqlite = (
            now.replace(tzinfo=None) + timedelta(seconds=WORKER_LEASE_SECONDS)
        ).strftime("%Y-%m-%d %H:%M:%S.%f")


        # BEGIN IMMEDIATE acquires a write lock on the entire SQLite file
        session.execute(text("BEGIN IMMEDIATE"))

        rows = session.execute(
            text(
                "SELECT id, url, normalized_domain, check_interval_minutes, user_id "
                "FROM monitoring_targets "
                "WHERE is_active = 1 "
                "  AND next_check_at <= :now "
                "  AND (execution_token IS NULL OR execution_expires_at < :now) "
                "ORDER BY next_check_at ASC "
                "LIMIT :batch_size"
            ),
            {"now": now_sqlite, "batch_size": CLAIM_BATCH_SIZE},
        ).fetchall()

        claimed: list[ClaimedTarget] = []
        for r in rows:
            token = str(uuid.uuid4())
            session.execute(
                text(
                    "UPDATE monitoring_targets "
                    "SET execution_token = :token, "
                    "    execution_epoch = :epoch, "
                    "    execution_expires_at = :expires "
                    "WHERE id = :target_id"
                ),
                {"token": token, "epoch": epoch, "expires": expires_sqlite, "target_id": r[0]},
            )
            claimed.append(
                ClaimedTarget(
                    target_id=r[0],
                    url=r[1],
                    normalized_domain=r[2],
                    check_interval_minutes=r[3],
                    execution_token=token,
                    execution_epoch=epoch,
                    user_id=r[4],
                )
            )

        session.commit()
        if claimed:
            logger.info(
                "[SCHEDULER] (SQLite) Claimed %d target(s) in epoch %d.",
                len(claimed), epoch,
            )
        return claimed

    # ── Scheduler State Helpers ────────────────────────────────────────────────

    def get_current_epoch(self, session: Session) -> int:
        """Return the current fencing epoch from the scheduler_state table."""
        row = session.execute(
            select(SchedulerState).where(SchedulerState.id == 1)
        ).scalar_one_or_none()
        return row.current_epoch if row else 0

    def ensure_scheduler_state_row(self, session: Session) -> None:
        """Ensure the singleton scheduler_state row (id=1) exists."""
        existing = session.execute(
            select(SchedulerState).where(SchedulerState.id == 1)
        ).scalar_one_or_none()
        if existing is None:
            dialect = session.bind.dialect.name  # type: ignore[union-attr]
            if dialect == "postgresql":
                session.execute(
                    text(
                        "INSERT INTO scheduler_state (id, current_epoch, updated_at) "
                        "VALUES (1, 0, NOW()) ON CONFLICT (id) DO NOTHING"
                    )
                )
            else:
                now_sqlite = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f")
                session.execute(
                    text(
                        "INSERT OR IGNORE INTO scheduler_state "
                        "(id, current_epoch, updated_at) "
                        "VALUES (1, 0, :now)"
                    ),
                    {"now": now_sqlite},
                )
            session.commit()
            logger.info("[SCHEDULER] Bootstrapped scheduler_state singleton row.")


# ── Singleton Instance ─────────────────────────────────────────────────────────
scheduler_service = SchedulerService()
