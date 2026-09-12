"""
tests/unit/test_scheduler_service.py
──────────────────────────────────────
Sprint 5 Phase 5A: Unit tests for SchedulerService.

Tests the following guarantees from the v1.2 specification:

Section 3  — Fencing epoch system (monotonic increment, atomic update)
Section 4  — Leader election (advisory lock emulation on SQLite)
Section 5  — Target claim loop (token assignment, batch limits)
Section 5.2 — Triple-predicate write-back (stale token, stale epoch, expired lease)
Section 9  — SQLite development contract (advisory lock emulation, SKIP LOCKED emulation)

All tests use an in-memory SQLite database (zero external dependencies).
No Redis, no network, no real Postgres advisory locks required.

Simulation-based tests from spec §14 that require real concurrent DB connections
will be implemented in tests/integration/test_scheduler_integration.py (Phase 5B).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import (
    Base,
    MonitoringTarget,
    SchedulerState,
    User,
)
from backend.services.scheduler_service import (
    CLAIM_BATCH_SIZE,
    SchedulerService,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    """In-memory SQLite engine with all tables created."""
    eng = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def session(engine):
    """Synchronous SQLite session."""
    session_local = sessionmaker(bind=engine)
    sess = session_local()
    yield sess
    sess.close()


@pytest.fixture
def service() -> SchedulerService:
    """Fresh SchedulerService instance for each test."""
    return SchedulerService()


@pytest.fixture
def user(session: Session) -> User:
    """A persisted test user."""
    u = User(email="scheduler-test@example.com", hashed_pw="hashed", role="user")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


@pytest.fixture
def active_target(session: Session, user: User) -> MonitoringTarget:
    """An active monitoring target ready for claiming (next_check_at in the past)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    t = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url="https://example.com",
        normalized_domain="example.com",
        check_interval_minutes=60,
        is_active=True,
        next_check_at=now - timedelta(minutes=5),  # Due 5 minutes ago
        consecutive_failures=0,
        user_id=user.id,
        created_at=now,
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


@pytest.fixture
def future_target(session: Session, user: User) -> MonitoringTarget:
    """A target whose next_check_at is in the future (should NOT be claimed)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    t = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url="https://future.example.com",
        normalized_domain="future.example.com",
        check_interval_minutes=60,
        is_active=True,
        next_check_at=now + timedelta(hours=1),
        consecutive_failures=0,
        user_id=user.id,
        created_at=now,
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


@pytest.fixture
def inactive_target(session: Session, user: User) -> MonitoringTarget:
    """A deactivated target that should never be claimed."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    t = MonitoringTarget(
        target_uuid=str(uuid.uuid4()),
        url="https://inactive.example.com",
        normalized_domain="inactive.example.com",
        check_interval_minutes=60,
        is_active=False,
        next_check_at=now - timedelta(minutes=5),
        consecutive_failures=0,
        user_id=user.id,
        created_at=now,
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


# ── Epoch / Scheduler State Tests ─────────────────────────────────────────────

class TestSchedulerStateBootstrap:
    """Tests for singleton scheduler_state row management."""

    def test_ensure_state_row_creates_singleton(self, service, session):
        """ensure_scheduler_state_row creates id=1 row when none exists."""
        service.ensure_scheduler_state_row(session)

        state = session.query(SchedulerState).filter_by(id=1).first()
        assert state is not None
        assert state.id == 1
        assert state.current_epoch == 0

    def test_ensure_state_row_idempotent(self, service, session):
        """ensure_scheduler_state_row is idempotent — calling twice is safe."""
        service.ensure_scheduler_state_row(session)
        service.ensure_scheduler_state_row(session)

        rows = session.query(SchedulerState).all()
        assert len(rows) == 1

    def test_get_current_epoch_returns_zero_on_empty(self, service, session):
        """get_current_epoch returns 0 when no row exists."""
        epoch = service.get_current_epoch(session)
        assert epoch == 0

    def test_get_current_epoch_returns_value(self, service, session):
        """get_current_epoch returns the stored epoch value."""
        service.ensure_scheduler_state_row(session)
        state = session.query(SchedulerState).filter_by(id=1).first()
        state.current_epoch = 7
        session.commit()

        assert service.get_current_epoch(session) == 7


# ── Leader Election Tests (SQLite Emulation) ───────────────────────────────────

class TestLeaderElection:
    """Tests for attempt_election() on SQLite (always-leader emulation)."""

    def test_election_returns_leader_on_sqlite(self, service, session):
        """SQLite dialect always returns LeaderState(is_leader=True)."""
        service.ensure_scheduler_state_row(session)
        result = service.attempt_election(session)

        assert result.is_leader is True
        assert result.epoch >= 1

    def test_election_increments_epoch(self, service, session):
        """Each successful election increments the epoch by exactly 1."""
        service.ensure_scheduler_state_row(session)

        result1 = service.attempt_election(session)
        epoch1 = result1.epoch

        result2 = service.attempt_election(session)
        epoch2 = result2.epoch

        assert epoch2 == epoch1 + 1

    def test_election_epoch_is_monotonic(self, service, session):
        """Epoch never decreases across successive elections."""
        service.ensure_scheduler_state_row(session)
        epochs = [service.attempt_election(session).epoch for _ in range(5)]

        for i in range(1, len(epochs)):
            assert epochs[i] > epochs[i - 1], (
                f"Epoch decreased at index {i}: {epochs[i - 1]} -> {epochs[i]}"
            )

    def test_election_persists_pod_id(self, service, session):
        """After election, scheduler_state reflects the current leader_pod_id."""
        from backend.services.scheduler_service import POD_ID
        service.ensure_scheduler_state_row(session)
        service.attempt_election(session)

        state = session.query(SchedulerState).filter_by(id=1).first()
        assert state.leader_pod_id == POD_ID

    def test_lease_renewal_succeeds_on_sqlite(self, service, session):
        """renew_lease always returns True on SQLite (single-leader emulation)."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)

        renewed = service.renew_lease(session, epoch=state.epoch)
        assert renewed is True

    def test_release_leadership_no_error_on_sqlite(self, service, session):
        """release_leadership() is a no-op on SQLite and raises no exception."""
        service.ensure_scheduler_state_row(session)
        service.attempt_election(session)
        service.release_leadership(session)  # Must not raise


# ── Target Claim Loop Tests ────────────────────────────────────────────────────

class TestTargetClaim:
    """Tests for claim_targets() SQLite path."""

    def test_claim_due_target(self, service, session, active_target, user):
        """A due active target is successfully claimed."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)

        claimed = service.claim_targets(session, epoch=state.epoch)

        assert len(claimed) == 1
        c = claimed[0]
        assert c.target_id == active_target.id
        assert c.url == active_target.url
        assert c.execution_epoch == state.epoch
        assert len(c.execution_token) == 36  # UUID v4
        assert c.user_id == user.id

    def test_future_target_not_claimed(self, service, session, future_target, user):
        """A target with next_check_at in the future is NOT claimed."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)

        claimed = service.claim_targets(session, epoch=state.epoch)

        assert len(claimed) == 0

    def test_inactive_target_not_claimed(self, service, session, inactive_target, user):
        """An inactive target is never claimed."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)

        claimed = service.claim_targets(session, epoch=state.epoch)

        assert len(claimed) == 0

    def test_already_claimed_target_not_double_claimed(
        self, service, session, active_target, user
    ):
        """
        A target that already has a valid non-expired execution_token
        should NOT be claimed again (SKIP LOCKED / BEGIN IMMEDIATE emulation).
        """
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)

        # First claim
        first_claims = service.claim_targets(session, epoch=state.epoch)
        assert len(first_claims) == 1

        # Second claim attempt — should find nothing new (token still valid)
        second_claims = service.claim_targets(session, epoch=state.epoch)
        assert len(second_claims) == 0, (
            "Target with a valid unexpired token was claimed twice."
        )

    def test_claim_assigns_unique_tokens(self, service, session, user):
        """Each claimed target gets a distinct UUID execution_token."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for i in range(3):
            t = MonitoringTarget(
                target_uuid=str(uuid.uuid4()),
                url=f"https://t{i}.example.com",
                normalized_domain=f"t{i}.example.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now - timedelta(minutes=i + 1),
                consecutive_failures=0,
                user_id=user.id,
                created_at=now,
            )
            session.add(t)
        session.commit()

        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = service.claim_targets(session, epoch=state.epoch)

        tokens = [c.execution_token for c in claimed]
        assert len(set(tokens)) == len(tokens), "Duplicate execution tokens assigned."

    def test_claim_respects_batch_size(self, service, session, user):
        """claim_targets never returns more than CLAIM_BATCH_SIZE targets."""
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        n = CLAIM_BATCH_SIZE + 5
        for i in range(n):
            t = MonitoringTarget(
                target_uuid=str(uuid.uuid4()),
                url=f"https://batch{i}.example.com",
                normalized_domain=f"batch{i}.example.com",
                check_interval_minutes=60,
                is_active=True,
                next_check_at=now - timedelta(minutes=i + 1),
                consecutive_failures=0,
                user_id=user.id,
                created_at=now,
            )
            session.add(t)
        session.commit()

        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = service.claim_targets(session, epoch=state.epoch)

        assert len(claimed) <= CLAIM_BATCH_SIZE, (
            f"Claimed {len(claimed)} targets; batch size limit is {CLAIM_BATCH_SIZE}."
        )

    def test_expired_token_allows_reclaim(self, service, session, user):
        """
        A target whose execution_expires_at has already passed can be
        re-claimed by a subsequent claim cycle.

        This verifies the stale-token reclaim predicate:
          execution_token IS NULL OR execution_expires_at < NOW()
        """
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        t = MonitoringTarget(
            target_uuid=str(uuid.uuid4()),
            url="https://expired.example.com",
            normalized_domain="expired.example.com",
            check_interval_minutes=60,
            is_active=True,
            next_check_at=now - timedelta(minutes=5),
            consecutive_failures=0,
            # Pre-assign an already-expired token
            execution_token=str(uuid.uuid4()),
            execution_epoch=1,
            execution_expires_at=now - timedelta(seconds=10),  # Already expired
            user_id=user.id,
            created_at=now,
        )
        session.add(t)
        session.commit()

        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = service.claim_targets(session, epoch=state.epoch)

        assert len(claimed) == 1, "Expired-token target was not re-claimed."
        assert claimed[0].target_id == t.id


# ── Write-Back Triple-Predicate Tests ─────────────────────────────────────────

class TestWriteBack:
    """Tests for write_back_result() triple-predicate stale-write safety (spec §5.2)."""

    def _do_claim(self, service, session, epoch):
        """Helper: claim targets and return the first ClaimedTarget."""
        claimed = service.claim_targets(session, epoch=epoch)
        assert claimed, "No targets were claimed."
        return claimed[0]

    def test_valid_writeback_commits(self, service, session, active_target, user):
        """A write-back with a valid token, epoch, and unexpired lease succeeds."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = self._do_claim(service, session, state.epoch)

        now = datetime.now(timezone.utc)
        result = service.write_back_result(
            session,
            target_id=claimed.target_id,
            execution_token=claimed.execution_token,
            execution_epoch=claimed.execution_epoch,
            last_checked_at=now,
            interval_minutes=60,
            last_prediction="BENIGN",
            last_confidence=0.95,
            consecutive_failures=0,
        )

        assert result is True

        session.expire_all()
        t = session.get(MonitoringTarget, active_target.id)
        assert t.execution_token is None
        assert t.execution_epoch is None
        assert t.last_prediction == "BENIGN"
        assert t.last_confidence == pytest.approx(0.95)

    def test_stale_token_writeback_is_noop(self, service, session, active_target, user):
        """
        Write-back with the WRONG execution_token produces 0 DB updates.
        Spec AC-04 and §5.2 invariant.
        """
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        self._do_claim(service, session, state.epoch)

        now = datetime.now(timezone.utc)
        result = service.write_back_result(
            session,
            target_id=active_target.id,
            execution_token="00000000-0000-0000-0000-000000000000",  # Wrong token
            execution_epoch=state.epoch,
            last_checked_at=now,
            interval_minutes=60,
            last_prediction="PHISHING",
            last_confidence=0.99,
            consecutive_failures=0,
        )

        assert result is False

        # Verify target was NOT updated
        session.expire_all()
        t = session.get(MonitoringTarget, active_target.id)
        assert t.last_prediction != "PHISHING"

    def test_stale_epoch_writeback_is_noop(self, service, session, active_target, user):
        """
        Write-back with the WRONG epoch (simulating a failover) produces 0 DB updates.
        Spec AC-04 and §5.2 epoch invariant.
        """
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = self._do_claim(service, session, state.epoch)

        now = datetime.now(timezone.utc)
        result = service.write_back_result(
            session,
            target_id=claimed.target_id,
            execution_token=claimed.execution_token,
            execution_epoch=state.epoch + 999,  # Epoch mismatch
            last_checked_at=now,
            interval_minutes=60,
            last_prediction="PHISHING",
            last_confidence=0.99,
            consecutive_failures=0,
        )

        assert result is False

        session.expire_all()
        t = session.get(MonitoringTarget, active_target.id)
        assert t.last_prediction != "PHISHING"

    def test_expired_lease_writeback_is_noop(self, service, session, user):
        """
        Write-back with an already-expired execution_expires_at produces 0 DB updates.
        Spec AC-05 and §5.2 lease expiry invariant.
        """
        # Manually create a target with an already-expired token
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stale_token = str(uuid.uuid4())
        stale_epoch = 42
        t = MonitoringTarget(
            target_uuid=str(uuid.uuid4()),
            url="https://leaseexpired.example.com",
            normalized_domain="leaseexpired.example.com",
            check_interval_minutes=60,
            is_active=True,
            next_check_at=now - timedelta(minutes=5),
            consecutive_failures=0,
            execution_token=stale_token,
            execution_epoch=stale_epoch,
            execution_expires_at=now - timedelta(seconds=5),  # Already expired
            user_id=user.id,
            created_at=now,
        )
        session.add(t)
        session.commit()

        result = service.write_back_result(
            session,
            target_id=t.id,
            execution_token=stale_token,
            execution_epoch=stale_epoch,
            last_checked_at=datetime.now(timezone.utc),
            interval_minutes=60,
            last_prediction="BENIGN",
            last_confidence=0.8,
            consecutive_failures=0,
        )

        assert result is False, "Expired lease write-back was not rejected."

        session.expire_all()
        t_reloaded = session.get(MonitoringTarget, t.id)
        assert t_reloaded.last_prediction is None
        # Token must still be present (write-back was rejected, not cleaned up)
        assert t_reloaded.execution_token == stale_token

    def test_writeback_clears_lease_columns(self, service, session, active_target, user):
        """A successful write-back sets execution_token/epoch/expires_at to NULL."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = self._do_claim(service, session, state.epoch)

        service.write_back_result(
            session,
            target_id=claimed.target_id,
            execution_token=claimed.execution_token,
            execution_epoch=claimed.execution_epoch,
            last_checked_at=datetime.now(timezone.utc),
            interval_minutes=60,
            last_prediction="BENIGN",
            last_confidence=0.9,
            consecutive_failures=0,
        )

        session.expire_all()
        t = session.get(MonitoringTarget, active_target.id)
        assert t.execution_token is None, "execution_token not cleared after write-back"
        assert t.execution_epoch is None, "execution_epoch not cleared after write-back"
        assert t.execution_expires_at is None, "execution_expires_at not cleared after write-back"

    def test_writeback_updates_next_check_at(self, service, session, active_target, user):
        """After successful write-back, next_check_at = last_checked_at + interval."""
        service.ensure_scheduler_state_row(session)
        state = service.attempt_election(session)
        claimed = self._do_claim(service, session, state.epoch)

        check_time = datetime.now(timezone.utc)
        service.write_back_result(
            session,
            target_id=claimed.target_id,
            execution_token=claimed.execution_token,
            execution_epoch=claimed.execution_epoch,
            last_checked_at=check_time,
            interval_minutes=30,
            last_prediction="BENIGN",
            last_confidence=0.9,
            consecutive_failures=0,
        )

        session.expire_all()
        t = session.get(MonitoringTarget, active_target.id)
        expected = check_time.replace(tzinfo=None) + timedelta(minutes=30)
        # Allow 1-second tolerance for naive datetime comparison
        assert abs((t.next_check_at - expected).total_seconds()) < 1


# ── Model Schema Tests ─────────────────────────────────────────────────────────

class TestSchedulerStateModel:
    """Tests verifying SchedulerState ORM model in SQLite."""

    def test_scheduler_state_table_created(self, engine):
        """scheduler_state table is created by Base.metadata.create_all."""
        from sqlalchemy import inspect as sa_inspect
        inspector = sa_inspect(engine)
        assert "scheduler_state" in inspector.get_table_names()

    def test_monitoring_target_has_execution_columns(self, engine):
        """monitoring_targets table has all three Phase 5A execution lease columns."""
        from sqlalchemy import inspect as sa_inspect
        inspector = sa_inspect(engine)
        cols = {c["name"] for c in inspector.get_columns("monitoring_targets")}
        assert "execution_token" in cols, "execution_token column missing"
        assert "execution_epoch" in cols, "execution_epoch column missing"
        assert "execution_expires_at" in cols, "execution_expires_at column missing"

    def test_scheduler_state_default_epoch_zero(self, session):
        """SchedulerState row inserted with default epoch=0."""
        state = SchedulerState(id=1, current_epoch=0)
        session.add(state)
        session.commit()

        loaded = session.get(SchedulerState, 1)
        assert loaded.current_epoch == 0

    def test_scheduler_state_epoch_increment(self, session):
        """current_epoch can be incremented atomically."""
        state = SchedulerState(id=1, current_epoch=3)
        session.add(state)
        session.commit()

        # Simulate epoch increment
        session.execute(
            text("UPDATE scheduler_state SET current_epoch = current_epoch + 1 WHERE id = 1")
        )
        session.commit()

        session.expire_all()
        loaded = session.get(SchedulerState, 1)
        assert loaded.current_epoch == 4


# ── Monitor Schema Tests ────────────────────────────────────────────────────────

class TestMonitorSchemas:
    """Tests for MonitoringTargetCreate and MonitoringTargetUpdate Pydantic schemas."""

    def test_valid_http_url_accepted(self):
        from backend.schemas.monitor import MonitoringTargetCreate
        m = MonitoringTargetCreate(url="http://example.com", check_interval_minutes=10)
        assert m.url == "http://example.com"

    def test_valid_https_url_accepted(self):
        from backend.schemas.monitor import MonitoringTargetCreate
        m = MonitoringTargetCreate(url="https://example.com/path?q=1")
        assert m.url == "https://example.com/path?q=1"

    def test_non_http_scheme_rejected(self):
        from pydantic import ValidationError

        from backend.schemas.monitor import MonitoringTargetCreate
        with pytest.raises(ValidationError, match="http or https"):
            MonitoringTargetCreate(url="ftp://example.com")

    def test_file_scheme_rejected(self):
        from pydantic import ValidationError

        from backend.schemas.monitor import MonitoringTargetCreate
        with pytest.raises(ValidationError):
            MonitoringTargetCreate(url="file:///etc/passwd")

    def test_interval_too_small_rejected(self):
        from pydantic import ValidationError

        from backend.schemas.monitor import MonitoringTargetCreate
        with pytest.raises(ValidationError):
            MonitoringTargetCreate(url="https://example.com", check_interval_minutes=1)

    def test_interval_too_large_rejected(self):
        from pydantic import ValidationError

        from backend.schemas.monitor import MonitoringTargetCreate
        with pytest.raises(ValidationError):
            MonitoringTargetCreate(url="https://example.com", check_interval_minutes=9999)

    def test_interval_boundary_5_accepted(self):
        from backend.schemas.monitor import MonitoringTargetCreate
        m = MonitoringTargetCreate(url="https://example.com", check_interval_minutes=5)
        assert m.check_interval_minutes == 5

    def test_interval_boundary_1440_accepted(self):
        from backend.schemas.monitor import MonitoringTargetCreate
        m = MonitoringTargetCreate(url="https://example.com", check_interval_minutes=1440)
        assert m.check_interval_minutes == 1440

    def test_update_all_none_valid(self):
        """MonitoringTargetUpdate with all None fields is valid (no-op patch)."""
        from backend.schemas.monitor import MonitoringTargetUpdate
        u = MonitoringTargetUpdate()
        assert u.check_interval_minutes is None
        assert u.is_active is None

    def test_update_activate_valid(self):
        from backend.schemas.monitor import MonitoringTargetUpdate
        u = MonitoringTargetUpdate(is_active=True)
        assert u.is_active is True

    def test_update_deactivate_valid(self):
        from backend.schemas.monitor import MonitoringTargetUpdate
        u = MonitoringTargetUpdate(is_active=False)
        assert u.is_active is False

    def test_extra_fields_forbidden(self):
        from pydantic import ValidationError

        from backend.schemas.monitor import MonitoringTargetCreate
        with pytest.raises(ValidationError):
            MonitoringTargetCreate(url="https://example.com", unknown_field="oops")
