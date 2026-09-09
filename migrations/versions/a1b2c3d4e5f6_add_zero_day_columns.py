"""Add zero-day ingestion columns to scan_results

Revision ID: a1b2c3d4e5f6
Revises: 25a29a701834
Create Date: 2026-09-09 18:00:00.000000

Sprint 2: Adds is_zero_day, feature_vector, and source_feed columns
to support zero-day URL tracking and the active learning pipeline.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "25a29a701834"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add zero-day ingestion columns."""
    op.add_column(
        "scan_results",
        sa.Column("is_zero_day", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_results",
        sa.Column("feature_vector", sa.JSON(), nullable=True),
    )
    op.add_column(
        "scan_results",
        sa.Column("source_feed", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    """Remove zero-day ingestion columns."""
    op.drop_column("scan_results", "source_feed")
    op.drop_column("scan_results", "feature_vector")
    op.drop_column("scan_results", "is_zero_day")
