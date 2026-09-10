"""Add retraining and label provenance columns to scan_results

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-10 20:30:00.000000

Sprint 3: Adds is_retrained, verified_label, label_provenance, and retrained_at
to support reliable active learning and prevent duplicate retraining loops.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: str | Sequence[str] | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add retraining metadata columns."""
    op.add_column(
        "scan_results",
        sa.Column("is_retrained", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.create_index("ix_scan_results_is_retrained", "scan_results", ["is_retrained"])
    op.add_column(
        "scan_results",
        sa.Column("verified_label", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("label_provenance", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("retrain_status", sa.String(length=32), nullable=False, server_default="UNVERIFIED"),
    )
    op.create_index("ix_scan_results_retrain_status", "scan_results", ["retrain_status"])
    op.add_column(
        "scan_results",
        sa.Column("retrain_attempt_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_results",
        sa.Column("last_retrain_attempt", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("retrained_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Remove retraining metadata columns."""
    op.drop_column("scan_results", "retrained_at")
    op.drop_column("scan_results", "last_retrain_attempt")
    op.drop_column("scan_results", "retrain_attempt_count")
    op.drop_index("ix_scan_results_retrain_status", table_name="scan_results")
    op.drop_column("scan_results", "retrain_status")
    op.drop_column("scan_results", "label_provenance")
    op.drop_column("scan_results", "verified_label")
    op.drop_index("ix_scan_results_is_retrained", table_name="scan_results")
    op.drop_column("scan_results", "is_retrained")
