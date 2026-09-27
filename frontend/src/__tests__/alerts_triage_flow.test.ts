/**
 * frontend/src/__tests__/alerts_triage_flow.test.ts
 * ─────────────────────────────────────────────────
 * Unit tests for Alert Triage state transitions, dismissal validation,
 * escalation payload contracts, and error handling.
 */

import { describe, expect, it } from 'vitest'
import type { AlertStatus } from '@/types/soc'

// Directed state machine transition rules (matching backend ALERT_STATUS_TRANSITIONS)
const ALLOWED_TRANSITIONS: Record<AlertStatus, Set<AlertStatus>> = {
  OPEN: new Set(['ACKNOWLEDGED', 'RESOLVED', 'DISMISSED']),
  ACKNOWLEDGED: new Set(['RESOLVED', 'DISMISSED', 'OPEN']),
  RESOLVED: new Set(['OPEN']),
  DISMISSED: new Set(['OPEN']),
}

export function isValidTransition(from: AlertStatus, to: AlertStatus): boolean {
  if (from === to) return true // Idempotent self-transition is permitted
  return ALLOWED_TRANSITIONS[from]?.has(to) ?? false
}

export function canAcknowledge(status: AlertStatus): boolean {
  return status === 'OPEN'
}

export function canResolve(status: AlertStatus): boolean {
  return status === 'OPEN' || status === 'ACKNOWLEDGED'
}

export function canDismiss(status: AlertStatus): boolean {
  return status === 'OPEN' || status === 'ACKNOWLEDGED'
}

export function canReopen(status: AlertStatus): boolean {
  return status === 'ACKNOWLEDGED' || status === 'RESOLVED' || status === 'DISMISSED'
}

export function validateDismissReason(reason: string): { isValid: boolean; error?: string } {
  const trimmed = (reason || '').trim()
  if (!trimmed) {
    return { isValid: false, error: 'Dismissal reason cannot be empty or whitespace.' }
  }
  if (trimmed.length > 255) {
    return { isValid: false, error: 'Dismissal reason exceeds 255 character limit.' }
  }
  return { isValid: true }
}

export function formatTriageErrorMessage(status: number, detail?: string): string {
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }
  switch (status) {
    case 400:
      return 'Alert state has changed or this transition is not allowed.'
    case 403:
      return 'Permission denied: Action requires authorized privileges.'
    case 404:
      return 'Alert not found or access denied.'
    case 409:
      return 'Conflict: Alert state was modified concurrently.'
    case 422:
      return 'Validation error: Please verify mandatory fields.'
    case 429:
      return 'Too many requests. Please wait a moment before trying again.'
    default:
      return 'Triage action failed. Please try again.'
  }
}

export function isSafeIndicatorUrl(indicator: string): boolean {
  if (!indicator) return false
  const lower = indicator.trim().toLowerCase()
  if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('vbscript:')) {
    return false
  }
  return lower.startsWith('http://') || lower.startsWith('https://')
}

describe('Alert Triage Lifecycle & Transition Rules', () => {
  it('allows valid transitions from OPEN', () => {
    expect(isValidTransition('OPEN', 'ACKNOWLEDGED')).toBe(true)
    expect(isValidTransition('OPEN', 'RESOLVED')).toBe(true)
    expect(isValidTransition('OPEN', 'DISMISSED')).toBe(true)
    expect(isValidTransition('OPEN', 'OPEN')).toBe(true) // Idempotent
  })

  it('allows valid transitions from ACKNOWLEDGED', () => {
    expect(isValidTransition('ACKNOWLEDGED', 'RESOLVED')).toBe(true)
    expect(isValidTransition('ACKNOWLEDGED', 'DISMISSED')).toBe(true)
    expect(isValidTransition('ACKNOWLEDGED', 'OPEN')).toBe(true) // Reopen / release claim
    expect(isValidTransition('ACKNOWLEDGED', 'ACKNOWLEDGED')).toBe(true)
  })

  it('prohibits direct terminal-to-terminal flips between RESOLVED and DISMISSED', () => {
    expect(isValidTransition('RESOLVED', 'DISMISSED')).toBe(false)
    expect(isValidTransition('DISMISSED', 'RESOLVED')).toBe(false)
    expect(isValidTransition('RESOLVED', 'ACKNOWLEDGED')).toBe(false)
    expect(isValidTransition('DISMISSED', 'ACKNOWLEDGED')).toBe(false)
  })

  it('permits reopening terminal alerts back to OPEN', () => {
    expect(isValidTransition('RESOLVED', 'OPEN')).toBe(true)
    expect(isValidTransition('DISMISSED', 'OPEN')).toBe(true)
  })

  it('correctly evaluates action availability predicates', () => {
    expect(canAcknowledge('OPEN')).toBe(true)
    expect(canAcknowledge('ACKNOWLEDGED')).toBe(false)
    expect(canAcknowledge('RESOLVED')).toBe(false)

    expect(canResolve('OPEN')).toBe(true)
    expect(canResolve('ACKNOWLEDGED')).toBe(true)
    expect(canResolve('RESOLVED')).toBe(false)

    expect(canDismiss('OPEN')).toBe(true)
    expect(canDismiss('ACKNOWLEDGED')).toBe(true)
    expect(canDismiss('DISMISSED')).toBe(false)

    expect(canReopen('OPEN')).toBe(false)
    expect(canReopen('ACKNOWLEDGED')).toBe(true)
    expect(canReopen('RESOLVED')).toBe(true)
    expect(canReopen('DISMISSED')).toBe(true)
  })
})

describe('Dismiss Reason Validation', () => {
  it('rejects empty or whitespace-only dismiss reasons', () => {
    expect(validateDismissReason('').isValid).toBe(false)
    expect(validateDismissReason('   ').isValid).toBe(false)
    expect(validateDismissReason('\t\n').isValid).toBe(false)
  })

  it('accepts valid non-empty dismissal justifications', () => {
    expect(validateDismissReason('False Positive — Known Good Internal Domain').isValid).toBe(true)
    expect(validateDismissReason('Risk accepted by security architect').isValid).toBe(true)
  })

  it('rejects excessively long dismissal reasons over 255 chars', () => {
    const tooLong = 'x'.repeat(256)
    expect(validateDismissReason(tooLong).isValid).toBe(false)
  })
})

describe('Triage Error Message Formatting', () => {
  it('formats standard HTTP status code errors gracefully', () => {
    expect(formatTriageErrorMessage(400)).toContain('Alert state has changed')
    expect(formatTriageErrorMessage(403)).toContain('Permission denied')
    expect(formatTriageErrorMessage(404)).toContain('Alert not found')
    expect(formatTriageErrorMessage(409)).toContain('Conflict')
    expect(formatTriageErrorMessage(422)).toContain('Validation error')
    expect(formatTriageErrorMessage(429)).toContain('Too many requests')
  })

  it('prioritizes server detail string when provided', () => {
    expect(formatTriageErrorMessage(400, 'Cannot transition alert from DISMISSED to RESOLVED.')).toBe(
      'Cannot transition alert from DISMISSED to RESOLVED.'
    )
  })
})

describe('Safe Indicator External Link Handling', () => {
  it('strictly rejects dangerous schemes like javascript:, data:, vbscript:', () => {
    expect(isSafeIndicatorUrl('javascript:alert(1)')).toBe(false)
    expect(isSafeIndicatorUrl('JAVASCRIPT:void(0)')).toBe(false)
    expect(isSafeIndicatorUrl('data:text/html,<script>alert(1)</script>')).toBe(false)
    expect(isSafeIndicatorUrl('vbscript:msgbox')).toBe(false)
  })

  it('accepts valid http and https URLs', () => {
    expect(isSafeIndicatorUrl('https://malicious-c2.example.com/payload')).toBe(true)
    expect(isSafeIndicatorUrl('http://192.168.1.100/scan')).toBe(true)
  })

  it('rejects plain domains or hashes without http/https schemes', () => {
    expect(isSafeIndicatorUrl('evil-phish.com')).toBe(false)
    expect(isSafeIndicatorUrl('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe(false)
  })
})
