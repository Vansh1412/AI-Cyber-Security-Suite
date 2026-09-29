/**
 * frontend/src/types/soc.ts
 * ──────────────────────────
 * Authoritative TypeScript domain definitions for Sprint 5 & 6 SOC features:
 * - Alerts & Triage
 * - Incidents Management
 * - Continuous Monitoring Targets & Diagnostics
 * - In-App Notifications & Webhooks
 * - Automated Threat Containment & SOAR Playbooks
 * - Server-Sent Events (SSE) Streaming Envelopes & Control Frames
 */

// ── Generic & Shared Enums ───────────────────────────────────────────────────

export type EventSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

// ── Alerts & Triage ──────────────────────────────────────────────────────────

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'DISMISSED'

export interface Alert {
  id: number
  alert_uuid: string
  title: string
  description: string | null
  severity: EventSeverity | string
  status: AlertStatus
  rule_name: string
  indicator_type: string
  indicator_value: string
  fingerprint: string | null
  occurrence_count: number
  first_seen_at: string
  last_seen_at: string
  acknowledged_at: string | null
  resolved_at: string | null
  dismissed_at: string | null
  dismiss_reason: string | null
  triage_notes: string | null
  user_id: number | null
  incident_id: number | null
}

export interface AlertAcknowledgeRequest {
  notes?: string
}

export interface AlertResolveRequest {
  resolution_notes?: string
}

export interface AlertDismissRequest {
  dismiss_reason: string
  triage_notes?: string
  notes?: string
}

export interface AlertReopenRequest {
  reopen_notes?: string
}

export interface AlertListResponse {
  items: Alert[]
  total: number
  page: number
  page_size: number
  has_next: boolean
}

export interface AlertStatsResponse {
  total_alerts: number
  open_alerts: number
  acknowledged_alerts: number
  resolved_alerts: number
  dismissed_alerts: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  alerts_last_24h: number
  alert_velocity_per_hour: number
  dedup_savings_ratio: number
}

// ── Incident Management ──────────────────────────────────────────────────────

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED'

export interface Incident {
  id: number
  incident_uuid: string
  title: string
  description: string | null
  severity: EventSeverity | string
  status: IncidentStatus
  assigned_to_user_id: number | null
  created_by_user_id: number | null
  created_at: string
  updated_at: string
  closed_at: string | null
  resolution_notes: string | null
  alert_count: number
  alerts?: Alert[]
  summary?: Record<string, unknown>
}

export interface IncidentCreate {
  title: string
  description?: string
  severity?: EventSeverity | string
  alert_ids?: number[]
}

export interface IncidentUpdate {
  title?: string
  description?: string
  severity?: EventSeverity | string
  status?: IncidentStatus
  assigned_to_user_id?: number | null
  resolution_notes?: string
}

export interface AttachAlertsRequest {
  alert_ids: number[]
}

// ── Continuous Monitoring Targets ────────────────────────────────────────────

export interface MonitoringTarget {
  id: number
  target_uuid: string
  url: string
  normalized_domain: string
  check_interval_minutes: number
  is_active: boolean
  last_checked_at: string | null
  next_check_at: string
  last_prediction: string | null
  last_confidence: number | null
  consecutive_failures: number
  last_status_code: number | null
  last_response_time_ms: number | null
  last_error_message: string | null
  execution_token: string | null
  execution_epoch: number | null
  execution_expires_at: string | null
  user_id: number
  created_at: string
}

export interface MonitoringTargetCreate {
  url: string
  check_interval_minutes?: number
}

export interface MonitoringTargetUpdate {
  check_interval_minutes?: number
  is_active?: boolean
}

export interface MonitoringTargetListResponse {
  items: MonitoringTarget[]
  total: number
  page: number
  page_size: number
}

export interface MonitoringTargetDiagnosticsResponse {
  target_uuid: string
  url: string
  is_active: boolean
  consecutive_failures: number
  last_checked_at: string | null
  last_status_code: number | null
  last_response_time_ms: number | null
  last_error_message: string | null
  last_prediction: string | null
  last_confidence: number | null
}

export interface MonitoringStatsResponse {
  total_targets: number
  active_targets: number
  paused_targets: number
  suspended_targets: number
  failing_targets: number
  scheduler_leader: string | null
  scheduler_epoch: number
  active_workers: number
  pool_capacity: number
}

export interface CheckNowResponse {
  target_uuid: string
  execution_token: string
  dispatched_at: string
  message: string
}

// ── In-App Notifications & Webhooks ──────────────────────────────────────────

export interface NotificationItem {
  id: number
  notification_uuid: string
  user_id: number
  title: string
  message: string
  severity: EventSeverity | string
  is_read: boolean
  link_url: string | null
  created_at: string
}

export interface NotificationListResponse {
  items: NotificationItem[]
  total: number
  unread_count: number
  page: number
  page_size: number
  has_next: boolean
}

export interface UnreadCountResponse {
  unread_count: number
}

export interface MarkAllReadResponse {
  updated_count: number
}

export interface NotificationPreferenceResponse {
  in_app_enabled: boolean
  email_enabled: boolean
  webhook_enabled: boolean
  webhook_url: string | null
  has_webhook_secret: boolean
  webhook_secret_preview: string | null
  min_severity: string
  circuit_broken: boolean
  circuit_broken_at: string | null
  updated_at: string
}

export interface NotificationPreferenceUpdate {
  in_app_enabled?: boolean
  email_enabled?: boolean
  webhook_enabled?: boolean
  webhook_url?: string | null
  webhook_secret?: string | null
  rotate_secret?: boolean
  clear_webhook_secret?: boolean
  min_severity?: string
}

// ── Containment & SOAR Playbooks ─────────────────────────────────────────────

export type ContainmentActionType =
  | 'BLACKLIST_INDICATOR'
  | 'INVALIDATE_CACHE'
  | 'QUARANTINE_TARGET'
  | 'CREATE_INCIDENT'
  | 'EMIT_SOC_EVENT'
  | 'SEND_NOTIFICATION'

export type ContainmentActionStatus =
  | 'PENDING'
  | 'EXECUTED'
  | 'FAILED'
  | 'BLOCKED_BY_ALLOWLIST'
  | 'SKIPPED'
  | 'REVERTED'

export type PlaybookRunStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'PARTIALLY_REVERTED'
  | 'REVERTED'

export interface ContainmentRequest {
  action_type: ContainmentActionType
  target_identifier: string
  alert_id?: number | null
  reason?: string
}

export interface ContainmentActionResponse {
  id: number
  action_uuid: string
  run_id: number | null
  tenant_id: number
  alert_id: number | null
  incident_id: number | null
  target_identifier: string
  action_type: string
  status: ContainmentActionStatus | string
  actor_user_id: number | null
  trigger_source: string
  action_idempotency_key: string
  rollback_metadata: Record<string, unknown> | null
  result_metadata: Record<string, unknown> | null
  error_message: string | null
  expires_at: string | null
  reverted_at: string | null
  reverted_by_user_id: number | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface PaginatedContainmentActions {
  items: ContainmentActionResponse[]
  total: number
  page: number
  page_size: number
}

export interface PlaybookRunResponse {
  id: number
  run_uuid: string
  playbook_name: string
  playbook_version: string
  tenant_id: number
  trigger_event: string
  alert_id: number | null
  target_id: number | null
  status: PlaybookRunStatus | string
  fencing_token: number
  action_count: number
  idempotency_key: string
  error_message: string | null
  started_at: string
  completed_at: string | null
  created_at: string
  updated_at: string
  actions: ContainmentActionResponse[]
}

export interface PaginatedPlaybookRuns {
  items: PlaybookRunResponse[]
  total: number
  page: number
  page_size: number
}

export interface ContainmentPolicyResponse {
  id: number
  tenant_id: number
  auto_containment_enabled: boolean
  auto_blacklist_enabled: boolean
  auto_quarantine_enabled: boolean
  auto_incident_binding_enabled: boolean
  containment_min_severity: string
  blacklist_ttl_seconds: number
  policy_version: number
  created_at: string
  updated_at: string
  updated_by: number | null
}

export interface ContainmentPolicyUpdate {
  auto_containment_enabled?: boolean
  auto_blacklist_enabled?: boolean
  auto_quarantine_enabled?: boolean
  auto_incident_binding_enabled?: boolean
  containment_min_severity?: string
  blacklist_ttl_seconds?: number
  policy_version: number
}

// ── SSE Real-Time Streaming Envelopes & Control ──────────────────────────────

export type StreamConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'auth_revoked'
  | 'error'

export interface SSEEventEnvelope<T = Record<string, unknown>> {
  cursor_id: number
  event_id: string
  event_type: string
  timestamp: string
  tenant_id: number
  channel: string
  aggregate_id?: string | null
  data: T
}

export interface StreamTicketResponse {
  ticket: string
  expires_in: number
  user_id: number
}

export interface StreamControlFrame {
  action?: string
  reason?: string
  last_delivered_id?: number
  reconnect_after?: number
  refresh?: boolean
}
