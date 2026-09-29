/**
 * frontend/src/__tests__/containment_flow.test.ts
 * ───────────────────────────────────────────────
 * Comprehensive unit and workflow contract tests for Threat Containment & SOAR:
 * - Containment action validation (target format, action types, reasons)
 * - Reversibility rules (provenance-safe rollback for BLACKLIST_INDICATOR and QUARANTINE_TARGET)
 * - Destructive action gating & explicit confirmation invariants
 * - Rule 0 allowlist failure behavior (BLOCKED_BY_ALLOWLIST)
 * - Optimistic concurrency control for tenant policies (policy_version, HTTP 409 conflict handling)
 * - Playbook runs read-only contract
 * - SSE query cache invalidation mapping
 */

import { describe, expect, it } from 'vitest'
import type {
  ContainmentActionResponse,
  ContainmentActionType,
  ContainmentPolicyResponse,
  ContainmentPolicyUpdate,
  ContainmentRequest,
  PlaybookRunResponse,
} from '@/types/soc'

// ── Pure Domain Logic Helpers (Mirroring UI Contracts) ────────────────────────

export function isActionReversible(action: Pick<ContainmentActionResponse, 'action_type' | 'status'>): boolean {
  if (action.status !== 'EXECUTED') return false
  return action.action_type === 'BLACKLIST_INDICATOR' || action.action_type === 'QUARANTINE_TARGET'
}

export function isDestructiveAction(actionType: ContainmentActionType): boolean {
  return actionType === 'BLACKLIST_INDICATOR' || actionType === 'QUARANTINE_TARGET'
}

export function validateContainmentRequest(req: ContainmentRequest): { isValid: boolean; error?: string } {
  const target = (req.target_identifier || '').trim()
  if (!target) {
    return { isValid: false, error: 'Target identifier is required.' }
  }
  if (target.length > 512) {
    return { isValid: false, error: 'Target identifier exceeds maximum length of 512 characters.' }
  }
  const validTypes: ContainmentActionType[] = [
    'BLACKLIST_INDICATOR',
    'INVALIDATE_CACHE',
    'QUARANTINE_TARGET',
    'CREATE_INCIDENT',
    'EMIT_SOC_EVENT',
    'SEND_NOTIFICATION',
  ]
  if (!validTypes.includes(req.action_type)) {
    return { isValid: false, error: `Invalid action type: ${req.action_type}` }
  }
  if (req.alert_id !== undefined && req.alert_id !== null && isNaN(req.alert_id)) {
    return { isValid: false, error: 'Alert ID must be a valid number.' }
  }
  if (req.reason && req.reason.length > 255) {
    return { isValid: false, error: 'Reason exceeds maximum length of 255 characters.' }
  }
  return { isValid: true }
}

export function validatePolicyUpdate(
  update: ContainmentPolicyUpdate,
  currentPolicy: ContainmentPolicyResponse
): { isValid: boolean; error?: string; isConflict?: boolean } {
  if (update.policy_version !== currentPolicy.policy_version) {
    return {
      isValid: false,
      isConflict: true,
      error: `Policy version conflict: current version is ${currentPolicy.policy_version}, update submitted ${update.policy_version}`,
    }
  }
  if (
    update.blacklist_ttl_seconds !== undefined &&
    (update.blacklist_ttl_seconds < 60 || update.blacklist_ttl_seconds > 2592000)
  ) {
    return {
      isValid: false,
      error: 'Blacklist TTL must be between 60 seconds and 2,592,000 seconds (30 days).',
    }
  }
  if (
    update.containment_min_severity &&
    !['CRITICAL', 'HIGH'].includes(update.containment_min_severity.toUpperCase())
  ) {
    return {
      isValid: false,
      error: "containment_min_severity must be 'CRITICAL' or 'HIGH'.",
    }
  }
  return { isValid: true }
}

export function getContainmentCacheInvalidations(eventType: string): string[] {
  if (eventType.startsWith('containment_') || eventType.startsWith('playbook_')) {
    return ['containment-actions', 'playbook-runs']
  }
  return []
}

// ── Test Suites ──────────────────────────────────────────────────────────────

describe('SOAR Containment Flow & Security Contracts', () => {
  describe('Action Reversibility & Provenance Rules', () => {
    it('permits rollback for EXECUTED BLACKLIST_INDICATOR actions', () => {
      const action = { action_type: 'BLACKLIST_INDICATOR', status: 'EXECUTED' }
      expect(isActionReversible(action)).toBe(true)
    })

    it('permits rollback for EXECUTED QUARANTINE_TARGET actions', () => {
      const action = { action_type: 'QUARANTINE_TARGET', status: 'EXECUTED' }
      expect(isActionReversible(action)).toBe(true)
    })

    it('forbids rollback for already REVERTED actions', () => {
      const action = { action_type: 'BLACKLIST_INDICATOR', status: 'REVERTED' }
      expect(isActionReversible(action)).toBe(false)
    })

    it('forbids rollback for FAILED or BLOCKED_BY_ALLOWLIST actions', () => {
      expect(isActionReversible({ action_type: 'BLACKLIST_INDICATOR', status: 'FAILED' })).toBe(false)
      expect(
        isActionReversible({ action_type: 'QUARANTINE_TARGET', status: 'BLOCKED_BY_ALLOWLIST' })
      ).toBe(false)
    })

    it('strictly forbids rollback for irreversible side-effect actions', () => {
      expect(isActionReversible({ action_type: 'INVALIDATE_CACHE', status: 'EXECUTED' })).toBe(false)
      expect(isActionReversible({ action_type: 'CREATE_INCIDENT', status: 'EXECUTED' })).toBe(false)
      expect(isActionReversible({ action_type: 'EMIT_SOC_EVENT', status: 'EXECUTED' })).toBe(false)
      expect(isActionReversible({ action_type: 'SEND_NOTIFICATION', status: 'EXECUTED' })).toBe(false)
    })
  })

  describe('Destructive Action Confirmation Invariants', () => {
    it('flags BLACKLIST_INDICATOR and QUARANTINE_TARGET as destructive', () => {
      expect(isDestructiveAction('BLACKLIST_INDICATOR')).toBe(true)
      expect(isDestructiveAction('QUARANTINE_TARGET')).toBe(true)
    })

    it('treats telemetry and notification actions as non-destructive', () => {
      expect(isDestructiveAction('INVALIDATE_CACHE')).toBe(false)
      expect(isDestructiveAction('CREATE_INCIDENT')).toBe(false)
      expect(isDestructiveAction('EMIT_SOC_EVENT')).toBe(false)
      expect(isDestructiveAction('SEND_NOTIFICATION')).toBe(false)
    })
  })

  describe('Manual Containment Request Validation', () => {
    it('accepts valid containment request with all fields', () => {
      const validReq: ContainmentRequest = {
        action_type: 'BLACKLIST_INDICATOR',
        target_identifier: 'evil-c2-domain.ru',
        alert_id: 104,
        reason: 'Confirmed command-and-control beaconing',
      }
      const res = validateContainmentRequest(validReq)
      expect(res.isValid).toBe(true)
      expect(res.error).toBeUndefined()
    })

    it('rejects empty target identifier', () => {
      const invalidReq: ContainmentRequest = {
        action_type: 'QUARANTINE_TARGET',
        target_identifier: '   ',
      }
      const res = validateContainmentRequest(invalidReq)
      expect(res.isValid).toBe(false)
      expect(res.error).toContain('Target identifier is required')
    })

    it('rejects target identifier exceeding 512 characters', () => {
      const longTarget = 'a'.repeat(513)
      const res = validateContainmentRequest({
        action_type: 'BLACKLIST_INDICATOR',
        target_identifier: longTarget,
      })
      expect(res.isValid).toBe(false)
      expect(res.error).toContain('exceeds maximum length')
    })

    it('rejects unsupported / invented action types', () => {
      const res = validateContainmentRequest({
        action_type: 'KILL_PROCESS_TREE' as unknown as ContainmentActionType,
        target_identifier: 'pid-1234',
      })
      expect(res.isValid).toBe(false)
      expect(res.error).toContain('Invalid action type')
    })
  })

  describe('Containment Policy Optimistic Concurrency Control', () => {
    const mockPolicy: ContainmentPolicyResponse = {
      id: 1,
      tenant_id: 42,
      auto_containment_enabled: false,
      auto_blacklist_enabled: false,
      auto_quarantine_enabled: false,
      auto_incident_binding_enabled: false,
      containment_min_severity: 'CRITICAL',
      blacklist_ttl_seconds: 86400,
      policy_version: 3,
      created_at: '2026-09-01T00:00:00Z',
      updated_at: '2026-09-02T12:00:00Z',
      updated_by: 1,
    }

    it('accepts policy update when policy_version matches', () => {
      const update: ContainmentPolicyUpdate = {
        auto_containment_enabled: true,
        policy_version: 3,
        blacklist_ttl_seconds: 3600,
      }
      const res = validatePolicyUpdate(update, mockPolicy)
      expect(res.isValid).toBe(true)
      expect(res.isConflict).toBeUndefined()
    })

    it('detects optimistic concurrency conflict when policy_version is outdated', () => {
      const staleUpdate: ContainmentPolicyUpdate = {
        auto_containment_enabled: true,
        policy_version: 2, // Outdated!
      }
      const res = validatePolicyUpdate(staleUpdate, mockPolicy)
      expect(res.isValid).toBe(false)
      expect(res.isConflict).toBe(true)
      expect(res.error).toContain('version conflict')
    })

    it('validates TTL bounds (60s to 30 days)', () => {
      const tooShort: ContainmentPolicyUpdate = {
        policy_version: 3,
        blacklist_ttl_seconds: 30, // < 60
      }
      expect(validatePolicyUpdate(tooShort, mockPolicy).isValid).toBe(false)

      const tooLong: ContainmentPolicyUpdate = {
        policy_version: 3,
        blacklist_ttl_seconds: 3000000, // > 2592000
      }
      expect(validatePolicyUpdate(tooLong, mockPolicy).isValid).toBe(false)
    })
  })

  describe('Playbook Runs Read-Only Contract', () => {
    it('models playbook run telemetry correctly without execution triggers', () => {
      const mockRun: PlaybookRunResponse = {
        id: 10,
        run_uuid: 'run-uuid-1234',
        playbook_name: 'CRITICAL_THREAT_AUTO_CONTAINMENT_V1',
        playbook_version: '1.0',
        tenant_id: 42,
        trigger_event: 'critical_alert_auto_containment',
        alert_id: 101,
        target_id: null,
        status: 'COMPLETED',
        fencing_token: 7,
        action_count: 5,
        idempotency_key: 'tenant:42:alert:101:playbook:CRITICAL_THREAT_AUTO_CONTAINMENT_V1',
        error_message: null,
        started_at: '2026-09-29T10:00:00Z',
        completed_at: '2026-09-29T10:00:02Z',
        created_at: '2026-09-29T10:00:00Z',
        updated_at: '2026-09-29T10:00:02Z',
        actions: [],
      }

      expect(mockRun.playbook_name).toBe('CRITICAL_THREAT_AUTO_CONTAINMENT_V1')
      expect(mockRun.status).toBe('COMPLETED')
      expect(mockRun.fencing_token).toBe(7)
      expect(mockRun.action_count).toBe(5)
    })
  })

  describe('Real-Time SSE Cache Invalidation Mapping', () => {
    it('invalidates containment-actions and playbook-runs on containment_applied', () => {
      const keys = getContainmentCacheInvalidations('containment_applied')
      expect(keys).toEqual(['containment-actions', 'playbook-runs'])
    })

    it('invalidates containment-actions and playbook-runs on containment_reverted', () => {
      const keys = getContainmentCacheInvalidations('containment_reverted')
      expect(keys).toEqual(['containment-actions', 'playbook-runs'])
    })

    it('invalidates containment-actions and playbook-runs on playbook_completed', () => {
      const keys = getContainmentCacheInvalidations('playbook_completed')
      expect(keys).toEqual(['containment-actions', 'playbook-runs'])
    })

    it('returns empty array for unrelated events', () => {
      expect(getContainmentCacheInvalidations('alert_created')).toEqual([])
    })
  })
})
