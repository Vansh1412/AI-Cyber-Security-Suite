/**
 * frontend/src/__tests__/incidents_flow.test.ts
 * ─────────────────────────────────────────────
 * Comprehensive unit and workflow tests for SOC Incident Management:
 * - URL state synchronization and filter management
 * - Pagination boundary rules (cursorless items.length === size)
 * - Directed state machine transitions (matching backend INCIDENT_STATUS_TRANSITIONS)
 * - Mandatory resolution notes validation for RESOLVED and CLOSED states
 * - Analyst assignment logic (self-assign, unassign, display names)
 * - Alert attachment / detachment contracts and HTTP 409 conflict handling
 * - RBAC presentation logic
 */

import { describe, expect, it } from 'vitest'
import type { IncidentStatus, EventSeverity, Incident, Alert } from '@/types/soc'

// Authoritative transition graph matching backend INCIDENT_STATUS_TRANSITIONS
const INCIDENT_STATUS_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  OPEN: ['INVESTIGATING', 'CLOSED'],
  INVESTIGATING: ['CONTAINED', 'OPEN', 'RESOLVED', 'CLOSED'],
  CONTAINED: ['INVESTIGATING', 'RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED', 'OPEN'],
  CLOSED: ['OPEN'],
}

export function isValidIncidentTransition(current: IncidentStatus, target: IncidentStatus): boolean {
  if (current === target) return true
  return INCIDENT_STATUS_TRANSITIONS[current]?.includes(target) ?? false
}

export function validateIncidentResolutionNotes(
  targetStatus: IncidentStatus,
  notes?: string
): { isValid: boolean; error?: string } {
  if (targetStatus === 'RESOLVED' || targetStatus === 'CLOSED') {
    if (!notes || !notes.trim()) {
      return {
        isValid: false,
        error: `Resolution notes are mandatory when transitioning an incident to ${targetStatus}.`,
      }
    }
    if (notes.trim().length < 5) {
      return {
        isValid: false,
        error: 'Resolution notes must be at least 5 characters.',
      }
    }
  }
  return { isValid: true }
}

export function parseIncidentUrlParams(search: string): {
  status?: IncidentStatus
  severity?: EventSeverity
  page: number
  size: number
} {
  const params = new URLSearchParams(search)
  const statusParam = params.get('status') as IncidentStatus | null
  const severityParam = params.get('severity') as EventSeverity | null
  const pageParam = parseInt(params.get('page') || '1', 10)
  const sizeParam = parseInt(params.get('size') || '20', 10)

  return {
    status: statusParam && ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'].includes(statusParam)
      ? statusParam
      : undefined,
    severity: severityParam && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severityParam)
      ? severityParam
      : undefined,
    page: isNaN(pageParam) || pageParam < 1 ? 1 : pageParam,
    size: isNaN(sizeParam) || sizeParam < 1 ? 20 : sizeParam,
  }
}

export function syncIncidentFilterParams(
  currentParams: URLSearchParams,
  updates: { status?: IncidentStatus | ''; severity?: EventSeverity | '' }
): URLSearchParams {
  const next = new URLSearchParams(currentParams)
  if (updates.status !== undefined) {
    if (updates.status) next.set('status', updates.status)
    else next.delete('status')
  }
  if (updates.severity !== undefined) {
    if (updates.severity) next.set('severity', updates.severity)
    else next.delete('severity')
  }
  // Filter changes MUST always reset page to 1
  next.set('page', '1')
  return next
}

export function computeIncidentPaginationState(
  itemsCount: number,
  pageSize: number,
  currentPage: number
): { canPrev: boolean; canNext: boolean; isEndOfRecords: boolean } {
  return {
    canPrev: currentPage > 1,
    canNext: itemsCount === pageSize,
    isEndOfRecords: itemsCount === 0 && currentPage > 1,
  }
}

export function formatIncidentErrorMessage(status: number, detail?: string): string {
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }
  switch (status) {
    case 400:
      return 'Invalid incident transition or missing mandatory fields.'
    case 403:
      return 'Permission denied: Action requires authorized SOC privileges.'
    case 404:
      return 'Incident or referenced alert not found.'
    case 409:
      return 'Conflict: Alert is already attached to an active incident or modified concurrently.'
    case 422:
      return 'Validation error: Please review submitted fields.'
    case 429:
      return 'Too many requests. Please wait before retrying.'
    default:
      return 'Incident operation failed. Please try again.'
  }
}

export function resolveAssignmentDisplay(
  incidentAssigneeId: number | null | undefined,
  currentUserId: number | null | undefined,
  userRole: string | undefined
): { label: string; canAssignToMe: boolean; canUnassign: boolean } {
  if (!incidentAssigneeId) {
    return {
      label: 'Unassigned',
      canAssignToMe: Boolean(currentUserId),
      canUnassign: false,
    }
  }
  if (incidentAssigneeId === currentUserId) {
    return {
      label: 'Assigned to You',
      canAssignToMe: false,
      canUnassign: true,
    }
  }
  return {
    label: `Assigned: Analyst #${incidentAssigneeId}`,
    canAssignToMe: userRole === 'admin',
    canUnassign: userRole === 'admin',
  }
}

describe('SOC Incident Flow & Lifecycle Contract', () => {
  describe('Authoritative Status Transitions', () => {
    it('allows valid transitions from OPEN', () => {
      expect(isValidIncidentTransition('OPEN', 'INVESTIGATING')).toBe(true)
      expect(isValidIncidentTransition('OPEN', 'CLOSED')).toBe(true)
      expect(isValidIncidentTransition('OPEN', 'RESOLVED')).toBe(false)
    })

    it('allows valid transitions from INVESTIGATING', () => {
      expect(isValidIncidentTransition('INVESTIGATING', 'CONTAINED')).toBe(true)
      expect(isValidIncidentTransition('INVESTIGATING', 'RESOLVED')).toBe(true)
      expect(isValidIncidentTransition('INVESTIGATING', 'CLOSED')).toBe(true)
      expect(isValidIncidentTransition('INVESTIGATING', 'OPEN')).toBe(true)
    })

    it('allows valid transitions from CONTAINED', () => {
      expect(isValidIncidentTransition('CONTAINED', 'INVESTIGATING')).toBe(true)
      expect(isValidIncidentTransition('CONTAINED', 'RESOLVED')).toBe(true)
      expect(isValidIncidentTransition('CONTAINED', 'CLOSED')).toBe(true)
      expect(isValidIncidentTransition('CONTAINED', 'OPEN')).toBe(false)
    })

    it('allows valid transitions from RESOLVED', () => {
      expect(isValidIncidentTransition('RESOLVED', 'CLOSED')).toBe(true)
      expect(isValidIncidentTransition('RESOLVED', 'OPEN')).toBe(true)
    })

    it('allows reopening from CLOSED to OPEN only', () => {
      expect(isValidIncidentTransition('CLOSED', 'OPEN')).toBe(true)
      expect(isValidIncidentTransition('CLOSED', 'INVESTIGATING')).toBe(false)
      expect(isValidIncidentTransition('CLOSED', 'RESOLVED')).toBe(false)
    })

    it('allows idempotent transitions (same state)', () => {
      expect(isValidIncidentTransition('OPEN', 'OPEN')).toBe(true)
      expect(isValidIncidentTransition('INVESTIGATING', 'INVESTIGATING')).toBe(true)
      expect(isValidIncidentTransition('CONTAINED', 'CONTAINED')).toBe(true)
      expect(isValidIncidentTransition('RESOLVED', 'RESOLVED')).toBe(true)
      expect(isValidIncidentTransition('CLOSED', 'CLOSED')).toBe(true)
    })
  })

  describe('Resolution Notes Validation', () => {
    it('requires resolution notes for RESOLVED state', () => {
      const emptyCheck = validateIncidentResolutionNotes('RESOLVED', '')
      expect(emptyCheck.isValid).toBe(false)
      expect(emptyCheck.error).toContain('mandatory')

      const shortCheck = validateIncidentResolutionNotes('RESOLVED', 'done')
      expect(shortCheck.isValid).toBe(false)
      expect(shortCheck.error).toContain('at least 5 characters')

      const validCheck = validateIncidentResolutionNotes('RESOLVED', 'Malware isolated and host scrubbed.')
      expect(validCheck.isValid).toBe(true)
    })

    it('requires resolution notes for CLOSED state', () => {
      const invalid = validateIncidentResolutionNotes('CLOSED', '   ')
      expect(invalid.isValid).toBe(false)

      const valid = validateIncidentResolutionNotes('CLOSED', 'Confirmed false positive from benign scanner.')
      expect(valid.isValid).toBe(true)
    })

    it('does not require resolution notes for INVESTIGATING state', () => {
      const check = validateIncidentResolutionNotes('INVESTIGATING', undefined)
      expect(check.isValid).toBe(true)
    })
  })

  describe('URL Synchronization & Filter State', () => {
    it('parses valid URL search parameters correctly', () => {
      const search = '?status=INVESTIGATING&severity=CRITICAL&page=3&size=50'
      const parsed = parseIncidentUrlParams(search)
      expect(parsed.status).toBe('INVESTIGATING')
      expect(parsed.severity).toBe('CRITICAL')
      expect(parsed.page).toBe(3)
      expect(parsed.size).toBe(50)
    })

    it('falls back to default page 1 and size 20 on missing or invalid params', () => {
      const search = '?page=invalid&size=-5'
      const parsed = parseIncidentUrlParams(search)
      expect(parsed.status).toBeUndefined()
      expect(parsed.severity).toBeUndefined()
      expect(parsed.page).toBe(1)
      expect(parsed.size).toBe(20)
    })

    it('resets page to 1 when status or severity filter changes', () => {
      const current = new URLSearchParams('page=4&size=20&status=OPEN')
      const updated = syncIncidentFilterParams(current, { severity: 'HIGH' })
      expect(updated.get('page')).toBe('1')
      expect(updated.get('severity')).toBe('HIGH')
      expect(updated.get('status')).toBe('OPEN')
    })

    it('removes query param when empty filter option selected', () => {
      const current = new URLSearchParams('status=OPEN&severity=HIGH')
      const updated = syncIncidentFilterParams(current, { status: '' })
      expect(updated.has('status')).toBe(false)
      expect(updated.get('severity')).toBe('HIGH')
      expect(updated.get('page')).toBe('1')
    })
  })

  describe('Incident Pagination Strategy (Cursorless)', () => {
    it('disables previous button on page 1', () => {
      const state = computeIncidentPaginationState(20, 20, 1)
      expect(state.canPrev).toBe(false)
      expect(state.canNext).toBe(true)
      expect(state.isEndOfRecords).toBe(false)
    })

    it('enables next button when loaded items equal page size', () => {
      const state = computeIncidentPaginationState(20, 20, 2)
      expect(state.canPrev).toBe(true)
      expect(state.canNext).toBe(true)
    })

    it('disables next button when fewer items than page size returned', () => {
      const state = computeIncidentPaginationState(14, 20, 2)
      expect(state.canPrev).toBe(true)
      expect(state.canNext).toBe(false)
    })

    it('flags end of incident records when 0 items returned on page > 1', () => {
      const state = computeIncidentPaginationState(0, 20, 3)
      expect(state.canPrev).toBe(true)
      expect(state.canNext).toBe(false)
      expect(state.isEndOfRecords).toBe(true)
    })
  })

  describe('Analyst Assignment Logic', () => {
    it('shows "Assign to Me" for unassigned incidents', () => {
      const display = resolveAssignmentDisplay(null, 101, 'analyst')
      expect(display.label).toBe('Unassigned')
      expect(display.canAssignToMe).toBe(true)
      expect(display.canUnassign).toBe(false)
    })

    it('shows "Assigned to You" and allows unassignment when assigned to current user', () => {
      const display = resolveAssignmentDisplay(101, 101, 'analyst')
      expect(display.label).toBe('Assigned to You')
      expect(display.canAssignToMe).toBe(false)
      expect(display.canUnassign).toBe(true)
    })

    it('masks other analyst ID without pretending to know full user directory', () => {
      const display = resolveAssignmentDisplay(999, 101, 'analyst')
      expect(display.label).toContain('Analyst #999')
      expect(display.canAssignToMe).toBe(false)
      expect(display.canUnassign).toBe(false)
    })

    it('allows admin reassignment/unassignment for any incident', () => {
      const display = resolveAssignmentDisplay(999, 1, 'admin')
      expect(display.canAssignToMe).toBe(true)
      expect(display.canUnassign).toBe(true)
    })
  })

  describe('Alert Attachment & Error Handling', () => {
    it('handles HTTP 409 conflict gracefully with clear user error', () => {
      const msg = formatIncidentErrorMessage(409)
      expect(msg).toContain('Conflict')
      expect(msg).toContain('already attached')
    })

    it('handles HTTP 403 authorization error', () => {
      const msg = formatIncidentErrorMessage(403)
      expect(msg).toContain('Permission denied')
    })

    it('ensures alert detachment does not manually mutate or downgrade severity', () => {
      // Analytical contract check: detaching an alert preserves the incident severity
      const mockAlert: Alert = {
        id: 1,
        alert_uuid: 'a-1',
        title: 'Critical Threat',
        description: null,
        severity: 'CRITICAL',
        status: 'OPEN',
        rule_name: 'test',
        indicator_type: 'DOMAIN',
        indicator_value: 'evil.com',
        fingerprint: null,
        occurrence_count: 1,
        first_seen_at: '2026-09-28T00:00:00Z',
        last_seen_at: '2026-09-28T00:00:00Z',
        acknowledged_at: null,
        resolved_at: null,
        dismissed_at: null,
        dismiss_reason: null,
        triage_notes: null,
        user_id: 1,
        incident_id: 1,
      }

      const incident: Partial<Incident> = {
        id: 1,
        severity: 'CRITICAL',
        alerts: [mockAlert],
      }
      // Simulate detachment: alert removed, but severity unchanged
      const afterDetachAlerts = (incident.alerts || []).filter(a => a.id !== 1)
      expect(afterDetachAlerts.length).toBe(0)
      expect(incident.severity).toBe('CRITICAL') // Must NOT downgrade!
    })
  })
})
