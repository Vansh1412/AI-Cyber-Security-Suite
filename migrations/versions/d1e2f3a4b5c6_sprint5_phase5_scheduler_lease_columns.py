"""sprint5_phase5_scheduler_lease_columns

Revision ID: d1e2f3a4b5c6
Revises: c5e6f7a8b9c0
Create Date: 2026-09-12 14:05:00.000000

Adds:
  - scheduler_state table (singleton id=1): distributed leader-election epoch
  - monitoring_targets: execution_token, execution_epoch, execution_expires_at

All new columns are nullable with NULL defaults → zero-downtime migration compatible.
The scheduler_state seed row insert is idempotent.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d1e2f3a4b5c6"
down_revision: str | Sequence[str] | None = "c5e6f7a8b9c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add scheduler_state table and execution lease columns to monitoring_targets."""
    conn = op.get_bind()
    dialect = conn.dialect.name

    # ── 1. Create scheduler_state singleton table ─────────────────────────────
    op.create_table(
        "scheduler_state",
        sa.Column("id", sa.Integer(), nullable=False, primary_key=True),
        sa.Column("current_epoch", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("leader_pod_id", sa.String(length=128), nullable=True),
        sa.Column("lease_acquired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_scheduler_state_id", "scheduler_state", ["id"])

    # Seed the singleton row (idempotent — safe to run even if row exists)
    conn.execute(
        sa.text(
            "INSERT INTO scheduler_state (id, current_epoch) "
            "VALUES (1, 0) "
            "ON CONFLICT (id) DO NOTHING"
            if dialect == "postgresql"
            else
            "INSERT OR IGNORE INTO scheduler_state (id, current_epoch) VALUES (1, 0)"
        )
    )

    # ── 2. Add execution lease columns to monitoring_targets ─────────────────
    if dialect == "sqlite":
        with op.batch_alter_table("monitoring_targets") as batch_op:
            batch_op.add_column(
                sa.Column("execution_token", sa.String(length=36), nullable=True)
            )
            batch_op.add_column(
                sa.Column("execution_epoch", sa.Integer(), nullable=True)
            )
            batch_op.add_column(
                sa.Column("execution_expires_at", sa.DateTime(timezone=True), nullable=True)
            )
    else:
        op.add_column(
            "monitoring_targets",
            sa.Column("execution_token", sa.String(length=36), nullable=True),
        )
        op.add_column(
            "monitoring_targets",
            sa.Column("execution_epoch", sa.Integer(), nullable=True),
        )
        op.add_column(
            "monitoring_targets",
            sa.Column("execution_expires_at", sa.DateTime(timezone=True), nullable=True),
        )

        # PostgreSQL-only partial index for efficient claim queries
        op.execute(
            sa.text(
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mon_targets_claim "
                "ON monitoring_targets (is_active, next_check_at) "
                "WHERE execution_token IS NULL OR execution_expires_at < NOW()"
            )
        )


def downgrade() -> None:
    """Remove Phase 5 scheduler columns and table."""
    conn = op.get_bind()
    dialect = conn.dialect.name

    if dialect == "postgresql":
        op.execute(sa.text("DROP INDEX IF EXISTS idx_mon_targets_claim"))
        op.drop_column("monitoring_targets", "execution_expires_at")
        op.drop_column("monitoring_targets", "execution_epoch")
        op.drop_column("monitoring_targets", "execution_token")
    else:
        with op.batch_alter_table("monitoring_targets") as batch_op:
            batch_op.drop_column("execution_expires_at")
            batch_op.drop_column("execution_epoch")
            batch_op.drop_column("execution_token")

    op.drop_index("ix_scheduler_state_id", table_name="scheduler_state")
    op.drop_table("scheduler_state")
