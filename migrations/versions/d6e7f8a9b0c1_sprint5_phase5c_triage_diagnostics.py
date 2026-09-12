"""sprint5_phase5c_triage_diagnostics

Revision ID: d6e7f8a9b0c1
Revises: d1e2f3a4b5c6
Create Date: 2026-09-12 23:55:00.000000

Adds:
  - alerts: dismissed_at, dismiss_reason, triage_notes
  - alerts indexes: idx_alerts_user_status, idx_alerts_user_last_seen
  - monitoring_targets: last_status_code, last_response_time_ms, last_error_message
  - monitoring_targets index: idx_mon_targets_user_status

All new columns are nullable with NULL defaults → zero-downtime migration compatible.
Uses op.batch_alter_table for SQLite compatibility.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6e7f8a9b0c1"
down_revision: str | Sequence[str] | None = "d1e2f3a4b5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add Phase 5C alert triage and target diagnostic columns and indexes."""
    # ── 1. Update alerts table ────────────────────────────────────────────────
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("dismiss_reason", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("triage_notes", sa.Text(), nullable=True))
        batch_op.create_index("idx_alerts_user_status", ["user_id", "status"], unique=False)
        batch_op.create_index("idx_alerts_user_last_seen", ["user_id", "last_seen_at"], unique=False)

    # ── 2. Update monitoring_targets table ────────────────────────────────────
    with op.batch_alter_table("monitoring_targets", schema=None) as batch_op:
        batch_op.add_column(sa.Column("last_status_code", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("last_response_time_ms", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("last_error_message", sa.String(length=512), nullable=True))
        batch_op.create_index(
            "idx_mon_targets_user_status",
            ["user_id", "is_active", "consecutive_failures"],
            unique=False,
        )


def downgrade() -> None:
    """Remove Phase 5C alert triage and target diagnostic columns and indexes."""
    with op.batch_alter_table("monitoring_targets", schema=None) as batch_op:
        batch_op.drop_index("idx_mon_targets_user_status")
        batch_op.drop_column("last_error_message")
        batch_op.drop_column("last_response_time_ms")
        batch_op.drop_column("last_status_code")

    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.drop_index("idx_alerts_user_last_seen")
        batch_op.drop_index("idx_alerts_user_status")
        batch_op.drop_column("triage_notes")
        batch_op.drop_column("dismiss_reason")
        batch_op.drop_column("dismissed_at")
