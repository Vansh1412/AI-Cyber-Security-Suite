"""sprint5_soc_monitoring_tables

Revision ID: c5e6f7a8b9c0
Revises: a85576e7e8e0
Create Date: 2026-09-12 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c5e6f7a8b9c0'
down_revision: str | Sequence[str] | None = 'a85576e7e8e0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema to add Sprint 5 SOC, Incident & Monitoring tables."""
    # 1. Create incidents table first (referenced by alerts)
    op.create_table(
        'incidents',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('incident_uuid', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='HIGH'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('assigned_to_user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_by_user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
    )
    op.create_index('ix_incidents_id', 'incidents', ['id'])
    op.create_index('ix_incidents_incident_uuid', 'incidents', ['incident_uuid'], unique=True)
    op.create_index('ix_incidents_severity', 'incidents', ['severity'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('ix_incidents_assigned_to_user_id', 'incidents', ['assigned_to_user_id'])
    op.create_index('ix_incidents_created_by_user_id', 'incidents', ['created_by_user_id'])
    op.create_index('idx_incidents_status_severity', 'incidents', ['status', 'severity'])

    # 2. Create alerts table (references incidents and users)
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('alert_uuid', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='MEDIUM'),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='OPEN'),
        sa.Column('rule_name', sa.String(length=128), nullable=False),
        sa.Column('indicator_type', sa.String(length=32), nullable=False),
        sa.Column('indicator_value', sa.String(length=512), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=True),
        sa.Column('occurrence_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
    )
    op.create_index('ix_alerts_id', 'alerts', ['id'])
    op.create_index('ix_alerts_alert_uuid', 'alerts', ['alert_uuid'], unique=True)
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    op.create_index('ix_alerts_status', 'alerts', ['status'])
    op.create_index('ix_alerts_indicator_value', 'alerts', ['indicator_value'])
    op.create_index('ix_alerts_fingerprint', 'alerts', ['fingerprint'])
    op.create_index('ix_alerts_user_id', 'alerts', ['user_id'])
    op.create_index('ix_alerts_incident_id', 'alerts', ['incident_id'])
    op.create_index('idx_alerts_status_severity', 'alerts', ['status', 'severity'])
    op.create_index('idx_alerts_indicator', 'alerts', ['indicator_type', 'indicator_value'])

    # 3. Create monitoring_targets table
    op.create_table(
        'monitoring_targets',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('target_uuid', sa.String(length=36), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('normalized_domain', sa.String(length=255), nullable=False),
        sa.Column('check_interval_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_check_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_prediction', sa.String(length=64), nullable=True),
        sa.Column('last_confidence', sa.Float(), nullable=True),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_monitoring_targets_id', 'monitoring_targets', ['id'])
    op.create_index('ix_monitoring_targets_target_uuid', 'monitoring_targets', ['target_uuid'], unique=True)
    op.create_index('ix_monitoring_targets_normalized_domain', 'monitoring_targets', ['normalized_domain'])
    op.create_index('ix_monitoring_targets_is_active', 'monitoring_targets', ['is_active'])
    op.create_index('ix_monitoring_targets_next_check_at', 'monitoring_targets', ['next_check_at'])
    op.create_index('ix_monitoring_targets_user_id', 'monitoring_targets', ['user_id'])
    op.create_index('idx_mon_targets_next_check', 'monitoring_targets', ['is_active', 'next_check_at'])

    # 4. Create notification_preferences table
    op.create_table(
        'notification_preferences',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('in_app_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('email_enabled', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('webhook_enabled', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('webhook_url', sa.Text(), nullable=True),
        sa.Column('webhook_secret', sa.String(length=255), nullable=True),
        sa.Column('min_severity', sa.String(length=32), nullable=False, server_default='HIGH'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_notification_preferences_id', 'notification_preferences', ['id'])

    # 5. Create notifications table
    op.create_table(
        'notifications',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('notification_uuid', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='INFO'),
        sa.Column('is_read', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('link_url', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_notifications_id', 'notifications', ['id'])
    op.create_index('ix_notifications_notification_uuid', 'notifications', ['notification_uuid'], unique=True)
    op.create_index('ix_notifications_user_id', 'notifications', ['user_id'])
    op.create_index('ix_notifications_is_read', 'notifications', ['is_read'])
    op.create_index('idx_notifications_user_read', 'notifications', ['user_id', 'is_read'])

    # 6. Create audit_events table
    op.create_table(
        'audit_events',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('event_uuid', sa.String(length=36), nullable=False),
        sa.Column('action', sa.String(length=128), nullable=False),
        sa.Column('actor_user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('target_resource', sa.String(length=128), nullable=False),
        sa.Column('resource_id', sa.String(length=128), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_events_id', 'audit_events', ['id'])
    op.create_index('ix_audit_events_event_uuid', 'audit_events', ['event_uuid'], unique=True)
    op.create_index('ix_audit_events_action', 'audit_events', ['action'])
    op.create_index('ix_audit_events_actor_user_id', 'audit_events', ['actor_user_id'])
    op.create_index('ix_audit_events_created_at', 'audit_events', ['created_at'])

    # 7. Add index to scan_results table
    op.create_index('idx_scan_results_user_created', 'scan_results', ['user_id', 'created_at'])


def downgrade() -> None:
    """Downgrade schema to remove Sprint 5 tables and indexes."""
    op.drop_index('idx_scan_results_user_created', table_name='scan_results')

    op.drop_table('audit_events')
    op.drop_table('notifications')
    op.drop_table('notification_preferences')
    op.drop_table('monitoring_targets')
    op.drop_table('alerts')
    op.drop_table('incidents')
