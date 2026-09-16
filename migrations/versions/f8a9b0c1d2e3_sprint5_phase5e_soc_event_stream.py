"""sprint5_phase5e_soc_event_stream

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-09-15 22:00:00.000000

Sprint 5 Phase 5E:
  - Creates append-only soc_event_stream table with monotonic 64-bit cursor_id.
  - Adds composite index idx_soc_events_tenant_cursor on (tenant_id, cursor_id).
  - Adds index idx_soc_events_created_at on (created_at).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f8a9b0c1d2e3"
down_revision: str | Sequence[str] | None = "e7f8a9b0c1d2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "soc_event_stream",
        sa.Column(
            "cursor_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            primary_key=True,
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(length=64), nullable=False, server_default="soc"),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("aggregate_id", sa.String(length=64), nullable=True),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["users.id"],
            name="fk_soc_event_stream_tenant_id",
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "idx_soc_events_event_id",
        "soc_event_stream",
        ["event_id"],
        unique=True,
    )
    op.create_index(
        "idx_soc_events_tenant_cursor",
        "soc_event_stream",
        ["tenant_id", "cursor_id"],
        unique=False,
    )
    op.create_index(
        "idx_soc_events_created_at",
        "soc_event_stream",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_soc_events_created_at", table_name="soc_event_stream")
    op.drop_index("idx_soc_events_tenant_cursor", table_name="soc_event_stream")
    op.drop_index("idx_soc_events_event_id", table_name="soc_event_stream")
    op.drop_table("soc_event_stream")
