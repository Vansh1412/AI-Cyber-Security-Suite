"""sprint5_phase5d_outbox_circuit_breaker

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
Create Date: 2026-09-13 18:00:00.000000

Sprint 5 Phase 5D:
  - Adds notification_preferences columns: encrypted_webhook_secret, consecutive_failures,
    circuit_broken, circuit_broken_at.
  - Adds notifications index: idx_notifications_user_created.
  - Creates notification_outbox table and indexes for durable transactional outbox delivery.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e7f8a9b0c1d2"
down_revision: str | Sequence[str] | None = "d6e7f8a9b0c1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── 1. Update notification_preferences ────────────────────────────────────
    with op.batch_alter_table("notification_preferences", schema=None) as batch_op:
        batch_op.add_column(sa.Column("encrypted_webhook_secret", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("circuit_broken", sa.Boolean(), nullable=False, server_default=sa.text("0"))
        )
        batch_op.add_column(
            sa.Column("circuit_broken_at", sa.DateTime(timezone=True), nullable=True)
        )

    # ── 2. Add Index to notifications ─────────────────────────────────────────
    with op.batch_alter_table("notifications", schema=None) as batch_op:
        batch_op.create_index("idx_notifications_user_created", ["user_id", "created_at"], unique=False)

    # ── 3. Create notification_outbox Table ───────────────────────────────────
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("outbox_uuid", sa.String(length=36), nullable=False, unique=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False, server_default="WEBHOOK"),
        sa.Column("destination_url", sa.Text(), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False, unique=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=64), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_outbox_claim", "notification_outbox", ["status", "next_attempt_at"], unique=False)
    op.create_index("idx_outbox_stale_lock", "notification_outbox", ["status", "locked_at"], unique=False)


def downgrade() -> None:
    op.drop_index("idx_outbox_stale_lock", table_name="notification_outbox")
    op.drop_index("idx_outbox_claim", table_name="notification_outbox")
    op.drop_table("notification_outbox")

    with op.batch_alter_table("notifications", schema=None) as batch_op:
        batch_op.drop_index("idx_notifications_user_created")

    with op.batch_alter_table("notification_preferences", schema=None) as batch_op:
        batch_op.drop_column("circuit_broken_at")
        batch_op.drop_column("circuit_broken")
        batch_op.drop_column("consecutive_failures")
        batch_op.drop_column("encrypted_webhook_secret")
