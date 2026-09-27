/**
 * frontend/src/__tests__/soc_services.test.ts
 * ───────────────────────────────────────────
 * Unit tests for SOC modular API clients:
 * - alertsService
 * - incidentsService
 * - monitoringService
 * - containmentService
 * - notificationsService
 * - streamsService
 * - HTTP error handling & status contracts (401, 403, 404, 409, 422, 429)
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import api from '@/services/api'
import { alertsService } from '@/services/soc/alerts'
import { incidentsService } from '@/services/soc/incidents'
import { monitoringService } from '@/services/soc/monitoring'
import { containmentService } from '@/services/soc/containment'
import { notificationsService } from '@/services/soc/notifications'
import { streamsService } from '@/services/soc/streams'

vi.mock('@/services/api', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

describe('alertsService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('listAlerts passes filtering and pagination params', async () => {
    const mockData = { items: [], total: 0, page: 1, page_size: 20, has_next: false }
    vi.mocked(api.get).mockResolvedValueOnce({ data: mockData })

    const res = await alertsService.listAlerts({ page: 2, severity: 'HIGH', status: 'OPEN' })
    expect(api.get).toHaveBeenCalledWith('/v1/alerts', {
      params: { page: 2, severity: 'HIGH', status: 'OPEN' },
    })
    expect(res).toEqual(mockData)
  })

  it('getAlertStats calls /v1/alerts/stats', async () => {
    const mockStats = { total_alerts: 42, open_alerts: 10 }
    vi.mocked(api.get).mockResolvedValueOnce({ data: mockStats })

    const res = await alertsService.getAlertStats()
    expect(api.get).toHaveBeenCalledWith('/v1/alerts/stats')
    expect(res).toEqual(mockStats)
  })

  it('acknowledgeAlert posts to /acknowledge with notes', async () => {
    const mockAlert = { id: 1, alert_uuid: 'al-123', status: 'ACKNOWLEDGED' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAlert })

    const res = await alertsService.acknowledgeAlert('al-123', { notes: 'Claimed by SOC' })
    expect(api.post).toHaveBeenCalledWith('/v1/alerts/al-123/acknowledge', {
      notes: 'Claimed by SOC',
    })
    expect(res.status).toBe('ACKNOWLEDGED')
  })

  it('resolveAlert posts to /resolve with resolution_notes', async () => {
    const mockAlert = { id: 1, alert_uuid: 'al-123', status: 'RESOLVED' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAlert })

    const res = await alertsService.resolveAlert('al-123', { resolution_notes: 'Remediated' })
    expect(api.post).toHaveBeenCalledWith('/v1/alerts/al-123/resolve', {
      resolution_notes: 'Remediated',
    })
    expect(res.status).toBe('RESOLVED')
  })

  it('dismissAlert posts required dismiss_reason', async () => {
    const mockAlert = { id: 1, alert_uuid: 'al-123', status: 'DISMISSED' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAlert })

    const res = await alertsService.dismissAlert('al-123', { dismiss_reason: 'False positive' })
    expect(api.post).toHaveBeenCalledWith('/v1/alerts/al-123/dismiss', {
      dismiss_reason: 'False positive',
    })
    expect(res.status).toBe('DISMISSED')
  })

  it('reopenAlert posts to /reopen', async () => {
    const mockAlert = { id: 1, alert_uuid: 'al-123', status: 'OPEN' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAlert })

    const res = await alertsService.reopenAlert('al-123', { reopen_notes: 'New IOC detected' })
    expect(api.post).toHaveBeenCalledWith('/v1/alerts/al-123/reopen', {
      reopen_notes: 'New IOC detected',
    })
    expect(res.status).toBe('OPEN')
  })
})

describe('incidentsService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('createIncident posts new incident data', async () => {
    const mockIncident = { id: 10, title: 'Major Phishing Campaign' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockIncident })

    const res = await incidentsService.createIncident({
      title: 'Major Phishing Campaign',
      severity: 'CRITICAL',
      alert_ids: [1, 2],
    })
    expect(api.post).toHaveBeenCalledWith('/v1/incidents', {
      title: 'Major Phishing Campaign',
      severity: 'CRITICAL',
      alert_ids: [1, 2],
    })
    expect(res).toEqual(mockIncident)
  })

  it('attachAlerts associates alerts to incident', async () => {
    const mockIncident = { id: 10, alert_count: 3 }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockIncident })

    const res = await incidentsService.attachAlerts('inc-uuid', { alert_ids: [3, 4] })
    expect(api.post).toHaveBeenCalledWith('/v1/incidents/inc-uuid/alerts', { alert_ids: [3, 4] })
    expect(res.alert_count).toBe(3)
  })

  it('detachAlert removes alert from incident', async () => {
    const mockIncident = { id: 10, alert_count: 2 }
    vi.mocked(api.delete).mockResolvedValueOnce({ data: mockIncident })

    const res = await incidentsService.detachAlert('inc-uuid', 3)
    expect(api.delete).toHaveBeenCalledWith('/v1/incidents/inc-uuid/alerts/3')
    expect(res.alert_count).toBe(2)
  })
})

describe('monitoringService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('pauseTarget, resumeTarget, and reactivateTarget call correct lifecycle endpoints', async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { target_uuid: 'tgt-1' } })

    await monitoringService.pauseTarget('tgt-1')
    expect(api.post).toHaveBeenCalledWith('/v1/monitor/targets/tgt-1/pause')

    await monitoringService.resumeTarget('tgt-1')
    expect(api.post).toHaveBeenCalledWith('/v1/monitor/targets/tgt-1/resume')

    await monitoringService.reactivateTarget('tgt-1')
    expect(api.post).toHaveBeenCalledWith('/v1/monitor/targets/tgt-1/reactivate')
  })

  it('checkNow dispatches on-demand probe', async () => {
    const mockCheck = { target_uuid: 'tgt-1', execution_token: 'tok-1', message: 'Probe dispatched' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockCheck })

    const res = await monitoringService.checkNow('tgt-1')
    expect(api.post).toHaveBeenCalledWith('/v1/monitor/targets/tgt-1/check-now')
    expect(res.message).toBe('Probe dispatched')
  })
})

describe('containmentService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('containAction executes typed containment', async () => {
    const mockAction = { action_uuid: 'act-1', status: 'EXECUTED' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAction })

    const res = await containmentService.containAction({
      action_type: 'BLACKLIST_INDICATOR',
      target_identifier: 'evil.com',
      reason: 'C2 domain identified',
    })
    expect(api.post).toHaveBeenCalledWith('/v1/soc/actions/contain', {
      action_type: 'BLACKLIST_INDICATOR',
      target_identifier: 'evil.com',
      reason: 'C2 domain identified',
    })
    expect(res.status).toBe('EXECUTED')
  })

  it('revertAction rolls back executed action', async () => {
    const mockAction = { action_uuid: 'act-1', status: 'REVERTED' }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockAction })

    const res = await containmentService.revertAction('act-1')
    expect(api.post).toHaveBeenCalledWith('/v1/soc/actions/act-1/revert')
    expect(res.status).toBe('REVERTED')
  })

  it('updatePolicy uses optimistic concurrency control version', async () => {
    const mockPolicy = { id: 1, policy_version: 2, auto_containment_enabled: true }
    vi.mocked(api.put).mockResolvedValueOnce({ data: mockPolicy })

    const res = await containmentService.updatePolicy({
      auto_containment_enabled: true,
      policy_version: 1,
    })
    expect(api.put).toHaveBeenCalledWith('/v1/soc/containment/policy', {
      auto_containment_enabled: true,
      policy_version: 1,
    })
    expect(res.policy_version).toBe(2)
  })
})

describe('notificationsService', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('getUnreadCount retrieves unread counter for badge', async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ data: { unread_count: 5 } })
    const res = await notificationsService.getUnreadCount()
    expect(api.get).toHaveBeenCalledWith('/v1/notifications/unread-count')
    expect(res.unread_count).toBe(5)
  })

  it('markAllRead calls /v1/notifications/mark-all-read', async () => {
    vi.mocked(api.post).mockResolvedValueOnce({ data: { updated_count: 5 } })
    const res = await notificationsService.markAllRead()
    expect(api.post).toHaveBeenCalledWith('/v1/notifications/mark-all-read')
    expect(res.updated_count).toBe(5)
  })
})

describe('streamsService and Security Verification', () => {
  it('buildStreamPath strictly forbids appending JWT access token to URLs', () => {
    const socPath = streamsService.buildStreamPath('soc')
    expect(socPath).toBe('/v1/soc/stream')
    expect(socPath).not.toContain('token=')
    expect(socPath).not.toContain('jwt=')
    expect(socPath).not.toContain('bearer=')

    const filteredPath = streamsService.buildStreamPath('alerts', 'HIGH')
    expect(filteredPath).toBe('/v1/alerts/stream?min_severity=HIGH')
    expect(filteredPath).not.toContain('token=')
  })

  it('createTicket exchanges token for opaque short-lived ticket', async () => {
    const mockTicket = { ticket: 'st_1234-abcd', expires_in: 30, user_id: 1 }
    vi.mocked(api.post).mockResolvedValueOnce({ data: mockTicket })

    const res = await streamsService.createTicket('soc')
    expect(api.post).toHaveBeenCalledWith('/v1/streams/ticket', { channel: 'soc' })
    expect(res.ticket).toBe('st_1234-abcd')
  })
})

describe('HTTP Error Status Handling Contract', () => {
  it('handles 401 Unauthorized rejection', async () => {
    const error401 = { response: { status: 401, data: { detail: 'Token expired' } } }
    vi.mocked(api.get).mockRejectedValueOnce(error401)

    await expect(alertsService.listAlerts()).rejects.toEqual(error401)
  })

  it('handles 403 Forbidden rejection', async () => {
    const error403 = { response: { status: 403, data: { detail: 'Admin required' } } }
    vi.mocked(api.get).mockRejectedValueOnce(error403)

    await expect(alertsService.listAlerts()).rejects.toEqual(error403)
  })

  it('handles 404 Not Found anti-enumeration rejection', async () => {
    const error404 = { response: { status: 404, data: { detail: 'Alert not found' } } }
    vi.mocked(api.get).mockRejectedValueOnce(error404)

    await expect(alertsService.getAlert('nonexistent-uuid')).rejects.toEqual(error404)
  })

  it('handles 409 Conflict rejection for suspended targets or lease conflicts', async () => {
    const error409 = { response: { status: 409, data: { detail: 'Target is suspended' } } }
    vi.mocked(api.post).mockRejectedValueOnce(error409)

    await expect(monitoringService.pauseTarget('tgt-1')).rejects.toEqual(error409)
  })

  it('handles 422 Unprocessable Entity rejection for validation errors', async () => {
    const error422 = { response: { status: 422, data: { detail: 'Invalid URL format' } } }
    vi.mocked(api.post).mockRejectedValueOnce(error422)

    await expect(monitoringService.registerTarget({ url: 'invalid-url' })).rejects.toEqual(error422)
  })

  it('handles 429 Too Many Requests rejection for rate limits', async () => {
    const error429 = { response: { status: 429, data: { detail: 'Rate limit exceeded' } } }
    vi.mocked(api.post).mockRejectedValueOnce(error429)

    await expect(monitoringService.checkNow('tgt-1')).rejects.toEqual(error429)
  })
})
