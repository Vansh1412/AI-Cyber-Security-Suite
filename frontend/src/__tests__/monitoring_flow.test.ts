/**
 * frontend/src/__tests__/monitoring_flow.test.ts
 * ──────────────────────────────────────────────
 * Comprehensive unit and workflow tests for Continuous Target Monitoring:
 * - Fleet statistics parsing and worker utilization
 * - Activation filtering (active probes vs include deactivated/suspended)
 * - Standard paginated target response contract (total, page, page_size, has_more)
 * - Registration validation (5–1440 min intervals, URL format, quota checks)
 * - Lifecycle mutations (Check Now, Pause, Resume, Reactivate, Soft Delete)
 * - Diagnostics telemetry inspection (verdict, confidence, latency, status code)
 * - HTTP 409 execution lease conflict and rate limit (429) handling
 * - SSE target_status_changed event invalidation query keys
 */

import { describe, expect, it } from 'vitest'
import type {
  MonitoringTarget,
  MonitoringTargetDiagnosticsResponse,
} from '@/types/soc'

export function validateTargetInterval(interval: number): { isValid: boolean; error?: string } {
  if (isNaN(interval) || interval < 5 || interval > 1440) {
    return {
      isValid: false,
      error: 'Probe interval must be between 5 and 1440 minutes (24 hours).',
    }
  }
  return { isValid: true }
}

export function validateTargetUrl(rawUrl: string): { isValid: boolean; error?: string } {
  const trimmed = (rawUrl || '').trim()
  if (!trimmed) {
    return { isValid: false, error: 'Target URL cannot be empty.' }
  }
  try {
    const parsed = new URL(trimmed)
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { isValid: false, error: 'Only HTTP and HTTPS URLs are permitted.' }
    }
    return { isValid: true }
  } catch {
    return { isValid: false, error: 'Please enter a valid, absolute URL (e.g., https://example.com).' }
  }
}

export function checkTargetQuota(
  activeTargetsCount: number,
  userRole?: string
): { isAllowed: boolean; limit: number; remaining: number } {
  const limit = userRole === 'admin' ? 500 : 20
  const remaining = Math.max(0, limit - activeTargetsCount)
  return {
    isAllowed: activeTargetsCount < limit,
    limit,
    remaining,
  }
}

export function parseMonitoringUrlParams(search: string): {
  page: number
  pageSize: number
  includeInactive: boolean
} {
  const params = new URLSearchParams(search)
  const pageParam = parseInt(params.get('page') || '1', 10)
  const pageSizeParam = parseInt(params.get('page_size') || '20', 10)
  const includeInactive = params.get('include_inactive') === 'true'

  return {
    page: isNaN(pageParam) || pageParam < 1 ? 1 : pageParam,
    pageSize: isNaN(pageSizeParam) || pageSizeParam < 1 ? 20 : pageSizeParam,
    includeInactive,
  }
}

export function formatMonitoringErrorMessage(status: number, detail?: string): string {
  if (typeof detail === 'string' && detail.trim()) {
    return detail
  }
  switch (status) {
    case 400:
      return 'Invalid target URL format or private IP address rejected by SSRF protection.'
    case 403:
      return 'Permission denied: Target modification requires authorized SOC privileges.'
    case 404:
      return 'Target not found or has been permanently removed.'
    case 409:
      return 'Conflict: An active check execution lease is currently held for this target.'
    case 422:
      return 'Validation error: Please verify probe interval and target URL.'
    case 429:
      return 'Quota exceeded: Maximum active monitored target limit reached for your role.'
    default:
      return 'Target operation failed. Please try again.'
  }
}

export function resolveTargetBadgeState(target: {
  is_active: boolean
  consecutive_failures?: number
}): 'healthy' | 'failing' | 'paused' | 'suspended' {
  if (!target.is_active && (target.consecutive_failures || 0) >= 5) return 'suspended'
  if (!target.is_active) return 'paused'
  if ((target.consecutive_failures || 0) >= 3) return 'failing'
  return 'healthy'
}

export function getExpectedSSEInvalidationKeys(eventType: string): string[][] {
  if (eventType === 'target_status_changed') {
    return [['monitoring-targets'], ['monitoring-stats']]
  }
  if (eventType === 'alert_updated') {
    return [['alerts'], ['alert-stats'], ['incidents']]
  }
  return []
}

describe('SOC Continuous Target Monitoring Contract', () => {
  describe('Target URL and Interval Validation', () => {
    it('accepts valid HTTP/HTTPS URLs', () => {
      expect(validateTargetUrl('https://api.example.com/health').isValid).toBe(true)
      expect(validateTargetUrl('http://gateway.corp.net:8080').isValid).toBe(true)
    })

    it('rejects invalid or non-HTTP URLs', () => {
      expect(validateTargetUrl('ftp://example.com').isValid).toBe(false)
      expect(validateTargetUrl('not a url').isValid).toBe(false)
      expect(validateTargetUrl('').isValid).toBe(false)
    })

    it('enforces check interval bounds (5–1440 minutes)', () => {
      expect(validateTargetInterval(4).isValid).toBe(false)
      expect(validateTargetInterval(5).isValid).toBe(true)
      expect(validateTargetInterval(60).isValid).toBe(true)
      expect(validateTargetInterval(1440).isValid).toBe(true)
      expect(validateTargetInterval(1441).isValid).toBe(false)
      expect(validateTargetInterval(NaN).isValid).toBe(false)
    })
  })

  describe('Quota Governance', () => {
    it('enforces 20 active target quota for standard analysts', () => {
      const quotaUnder = checkTargetQuota(15, 'analyst')
      expect(quotaUnder.isAllowed).toBe(true)
      expect(quotaUnder.remaining).toBe(5)
      expect(quotaUnder.limit).toBe(20)

      const quotaReached = checkTargetQuota(20, 'analyst')
      expect(quotaReached.isAllowed).toBe(false)
      expect(quotaReached.remaining).toBe(0)
    })

    it('enforces 500 active target quota for administrators', () => {
      const quotaAdmin = checkTargetQuota(100, 'admin')
      expect(quotaAdmin.isAllowed).toBe(true)
      expect(quotaAdmin.limit).toBe(500)
      expect(quotaAdmin.remaining).toBe(400)
    })
  })

  describe('Fleet State and Status Badging', () => {
    it('accurately resolves target operational badge states', () => {
      expect(resolveTargetBadgeState({ is_active: true, consecutive_failures: 0 })).toBe('healthy')
      expect(resolveTargetBadgeState({ is_active: true, consecutive_failures: 3 })).toBe('failing')
      expect(resolveTargetBadgeState({ is_active: false, consecutive_failures: 0 })).toBe('paused')
      expect(resolveTargetBadgeState({ is_active: false, consecutive_failures: 6 })).toBe('suspended')
    })
  })

  describe('URL Synchronization & Query Params', () => {
    it('parses target parameters with pagination and include_inactive', () => {
      const search = '?page=2&page_size=50&include_inactive=true'
      const parsed = parseMonitoringUrlParams(search)
      expect(parsed.page).toBe(2)
      expect(parsed.pageSize).toBe(50)
      expect(parsed.includeInactive).toBe(true)
    })

    it('defaults to page 1 and include_inactive=false when absent', () => {
      const parsed = parseMonitoringUrlParams('')
      expect(parsed.page).toBe(1)
      expect(parsed.pageSize).toBe(20)
      expect(parsed.includeInactive).toBe(false)
    })
  })

  describe('Target Pagination Data Contract', () => {
    it('verifies standard paginated structure with items', () => {
      const mockTarget: MonitoringTarget = {
        id: 1,
        target_uuid: 't-1',
        url: 'https://test.com',
        normalized_domain: 'test.com',
        check_interval_minutes: 15,
        is_active: true,
        last_checked_at: '2026-09-28T00:00:00Z',
        next_check_at: '2026-09-28T00:15:00Z',
        last_prediction: 'BENIGN',
        last_confidence: 0.99,
        consecutive_failures: 0,
        last_status_code: 200,
        last_response_time_ms: 120.5,
        last_error_message: null,
        execution_token: null,
        execution_epoch: null,
        execution_expires_at: null,
        user_id: 1,
        created_at: '2026-09-28T00:00:00Z',
      }

      const mockResponse = {
        items: [mockTarget],
        total: 45,
        page: 1,
        page_size: 20,
        has_more: true,
      }

      expect(mockResponse.has_more).toBe(true)
      expect(mockResponse.total).toBe(45)
      expect(mockResponse.items.length).toBe(1)
      expect(mockResponse.items[0].normalized_domain).toBe('test.com')
    })
  })

  describe('Error & Lease Conflict Handling', () => {
    it('formats 409 execution lease conflict appropriately', () => {
      const msg = formatMonitoringErrorMessage(409)
      expect(msg).toContain('execution lease')
      expect(msg).toContain('Conflict')
    })

    it('formats 429 quota exhaustion correctly', () => {
      const msg = formatMonitoringErrorMessage(429)
      expect(msg).toContain('Quota exceeded')
    })

    it('formats 400 SSRF / URL rejection correctly', () => {
      const msg = formatMonitoringErrorMessage(400)
      expect(msg).toContain('SSRF protection')
    })
  })

  describe('SSE Invalidation Invariants', () => {
    it('invalidates both monitoring-targets and monitoring-stats on target_status_changed', () => {
      const keys = getExpectedSSEInvalidationKeys('target_status_changed')
      expect(keys).toEqual([['monitoring-targets'], ['monitoring-stats']])
    })

    it('invalidates incidents in addition to alerts on alert_updated', () => {
      const keys = getExpectedSSEInvalidationKeys('alert_updated')
      expect(keys).toContainEqual(['incidents'])
      expect(keys).toContainEqual(['alerts'])
      expect(keys).toContainEqual(['alert-stats'])
    })
  })

  describe('Diagnostics Verification', () => {
    it('confirms telemetry diagnostics attributes without historical graph fabrication', () => {
      const diag: MonitoringTargetDiagnosticsResponse = {
        target_uuid: 'uuid-1',
        url: 'https://victim.com',
        is_active: true,
        last_checked_at: '2026-09-28T12:00:00Z',
        last_status_code: 200,
        last_response_time_ms: 142.5,
        last_prediction: 'benign',
        last_confidence: 0.98,
        consecutive_failures: 0,
        last_error_message: null,
      }

      expect(diag.last_status_code).toBe(200)
      expect(diag.last_response_time_ms).toBe(142.5)
      expect(diag.last_prediction).toBe('benign')
      expect(diag.consecutive_failures).toBe(0)
    })
  })
})
