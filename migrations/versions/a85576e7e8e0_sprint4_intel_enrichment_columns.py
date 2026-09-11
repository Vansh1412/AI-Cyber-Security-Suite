"""sprint4_intel_enrichment_columns

Revision ID: a85576e7e8e0
Revises: b2c3d4e5f6a7
Create Date: 2026-09-11 21:29:35.798192

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a85576e7e8e0'
down_revision: str | Sequence[str] | None = 'b2c3d4e5f6a7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('scan_results') as batch_op:
        batch_op.add_column(sa.Column('domain_age_days', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('tls_valid', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('redirect_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('final_url', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('threat_intel_enrichment', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('scan_results') as batch_op:
        batch_op.drop_column('threat_intel_enrichment')
        batch_op.drop_column('final_url')
        batch_op.drop_column('redirect_count')
        batch_op.drop_column('tls_valid')
        batch_op.drop_column('domain_age_days')
