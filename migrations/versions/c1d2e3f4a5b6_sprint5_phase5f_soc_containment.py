"""sprint5_phase5f_soc_containment

Revision ID: c1d2e3f4a5b6
Revises: f8a9b0c1d2e3
Create Date: 2026-09-20 22:30:00.000000

Sprint 5 Phase 5F:
  - Creates soc_containment_policies table for tenant containment configuration.
  - Creates soc_playbook_runs table for declarative playbook execution tracking.
  - Creates soc_containment_actions table for durable action persistence and rollback metadata.
  - Creates soc_dynamic_blacklist table for automated/analyst indicator containment with TTL.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1d2e3f4a5b6"
down_revision: str | Sequence[str] | None = "f8a9b0c1d2e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. soc_containment_policies
    op.create_table(
        "soc_containment_policies",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("auto_containment_enabled", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("auto_blacklist_enabled", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("auto_quarantine_enabled", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("auto_incident_binding_enabled", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("containment_min_severity", sa.String(length=16), server_default="CRITICAL", nullable=False),
        sa.Column("blacklist_ttl_seconds", sa.Integer(), server_default="86400", nullable=False),
        sa.Column("policy_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.CheckConstraint("containment_min_severity IN ('CRITICAL', 'HIGH')", name="chk_min_severity"),
        sa.CheckConstraint("blacklist_ttl_seconds >= 60 AND blacklist_ttl_seconds <= 2592000", name="chk_blacklist_ttl"),
    )
    op.create_index("idx_containment_policies_tenant", "soc_containment_policies", ["tenant_id"])

    # 2. soc_playbook_runs
    op.create_table(
        "soc_playbook_runs",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("run_uuid", sa.String(length=36), nullable=False, unique=True),
        sa.Column("playbook_name", sa.String(length=128), nullable=False),
        sa.Column("playbook_version", sa.String(length=32), server_default="1.0", nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("trigger_event", sa.String(length=64), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("monitoring_targets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("fencing_token", sa.Integer(), server_default="1", nullable=False),
        sa.Column("action_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'PARTIALLY_REVERTED', 'REVERTED')",
            name="chk_run_status",
        ),
    )
    op.create_index("idx_playbook_runs_tenant_status", "soc_playbook_runs", ["tenant_id", "status"])
    op.create_index("idx_playbook_runs_alert", "soc_playbook_runs", ["alert_id"])

    # 3. soc_containment_actions
    op.create_table(
        "soc_containment_actions",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("action_uuid", sa.String(length=36), nullable=False, unique=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("soc_playbook_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_identifier", sa.String(length=512), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("trigger_source", sa.String(length=64), nullable=False),
        sa.Column("action_idempotency_key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("rollback_metadata", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("result_metadata", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reverted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reverted_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('PENDING', 'EXECUTED', 'FAILED', 'BLOCKED_BY_ALLOWLIST', 'SKIPPED', 'REVERTED')",
            name="chk_action_status",
        ),
        sa.CheckConstraint(
            "action_type IN ('BLACKLIST_INDICATOR', 'INVALIDATE_CACHE', 'QUARANTINE_TARGET', 'CREATE_INCIDENT', 'EMIT_SOC_EVENT', 'SEND_NOTIFICATION')",
            name="chk_action_type",
        ),
    )
    op.create_index("idx_containment_actions_tenant_status", "soc_containment_actions", ["tenant_id", "status"])
    op.create_index("idx_containment_actions_target", "soc_containment_actions", ["target_identifier"])

    # 4. soc_dynamic_blacklist
    op.create_table(
        "soc_dynamic_blacklist",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("indicator_type", sa.String(length=32), nullable=False),
        sa.Column("indicator_value", sa.String(length=512), nullable=False),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("containment_action_id", sa.Integer(), sa.ForeignKey("soc_containment_actions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reason", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("indicator_type IN ('url', 'domain', 'ip')", name="chk_indicator_type"),
    )
    op.create_index("idx_dynamic_blacklist_indicator", "soc_dynamic_blacklist", ["indicator_value", "is_active"])
    op.create_index("idx_dynamic_blacklist_tenant", "soc_dynamic_blacklist", ["tenant_id", "is_active"])
    op.create_index("idx_dynamic_blacklist_expires", "soc_dynamic_blacklist", ["expires_at"])


def downgrade() -> None:
    op.drop_table("soc_dynamic_blacklist")
    op.drop_table("soc_containment_actions")
    op.drop_table("soc_playbook_runs")
    op.drop_table("soc_containment_policies")
