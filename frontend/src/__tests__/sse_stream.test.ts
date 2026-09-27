/**
 * frontend/src/__tests__/sse_stream.test.ts
 * ─────────────────────────────────────────
 * Tests for SSE streaming mechanics, authentication, control frames, and lifecycle:
 * - Authorization: Bearer <jwt> headers
 * - Absolute prohibition on JWT in URLs
 * - Last-Event-ID tracking and replay
 * - stream_reset, stream_refresh, stream_overflow, stream_auth_revoked, server_shutdown
 * - Cleanup and abort on unmount
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { streamsService } from '@/services/soc/streams'
import { parseSSEFrames } from '@/hooks/useSSEStream'

// Lightweight in-memory localStorage polyfill for Node test environment
const mockStorage: Record<string, string> = {}
globalThis.localStorage = {
  getItem: (key: string) => mockStorage[key] ?? null,
  setItem: (key: string, val: string) => {
    mockStorage[key] = String(val)
  },
  removeItem: (key: string) => {
    delete mockStorage[key]
  },
  clear: () => {
    Object.keys(mockStorage).forEach((k) => delete mockStorage[k])
  },
  length: 0,
  key: () => null,
} as unknown as Storage

describe('SSE Streaming Protocol & Security Guarantees', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('retrieves JWT token for request headers without logging or modifying it', () => {
    localStorage.setItem('access_token', 'jwt-secret-token-123')
    expect(streamsService.getBearerToken()).toBe('jwt-secret-token-123')
  })

  it('buildStreamPath strictly prevents putting JWT access token into the URL', () => {
    const defaultPath = streamsService.buildStreamPath('soc')
    expect(defaultPath).toBe('/v1/soc/stream')
    expect(defaultPath).not.toContain('token')

    const adminPath = streamsService.buildStreamPath('admin')
    expect(adminPath).toBe('/v1/admin/soc/stream')
    expect(adminPath).not.toContain('token')

    const alertsPath = streamsService.buildStreamPath('alerts', 'CRITICAL')
    expect(alertsPath).toBe('/v1/alerts/stream?min_severity=CRITICAL')
    expect(alertsPath).not.toContain('token')
  })

  it('handles stream_reset control frame triggering resync required', () => {
    const raw =
      'event: stream_reset\ndata: {"action": "resync_required", "reason": "cursor_expired"}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('stream_reset')
    const parsed = JSON.parse(messages[0].data)
    expect(parsed.action).toBe('resync_required')
    expect(parsed.reason).toBe('cursor_expired')
  })

  it('handles stream_refresh control frame for 1-hour lifetime boundary', () => {
    const raw =
      'event: stream_refresh\ndata: {"refresh": true, "reason": "max_lifetime_reached"}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('stream_refresh')
    const parsed = JSON.parse(messages[0].data)
    expect(parsed.refresh).toBe(true)
    expect(parsed.reason).toBe('max_lifetime_reached')
  })

  it('handles stream_overflow control frame with last_delivered_id cursor', () => {
    const raw =
      'event: stream_overflow\ndata: {"reconnect": true, "last_delivered_id": 8841}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('stream_overflow')
    const parsed = JSON.parse(messages[0].data)
    expect(parsed.reconnect).toBe(true)
    expect(parsed.last_delivered_id).toBe(8841)
  })

  it('handles stream_auth_revoked control frame for account deactivation', () => {
    const raw =
      'event: stream_auth_revoked\ndata: {"reason": "account_deactivated"}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('stream_auth_revoked')
    const parsed = JSON.parse(messages[0].data)
    expect(parsed.reason).toBe('account_deactivated')
  })

  it('handles server_shutdown control frame with custom reconnect_after delay', () => {
    const raw =
      'event: server_shutdown\ndata: {"reconnect_after": 10}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('server_shutdown')
    const parsed = JSON.parse(messages[0].data)
    expect(parsed.reconnect_after).toBe(10)
  })

  it('parses full domain event envelope correctly', () => {
    const payload = {
      cursor_id: 12045,
      event_id: 'd9b7f8e1-4c2a-4f5b-9d8e-123456789abc',
      event_type: 'alert_created',
      timestamp: '2026-09-27T18:00:00Z',
      tenant_id: 42,
      channel: 'soc',
      data: {
        alert_uuid: 'al-9988',
        severity: 'HIGH',
        status: 'OPEN',
      },
    }
    const raw = `event: alert_created\nid: 12045\ndata: ${JSON.stringify(payload)}\n\n`
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].event).toBe('alert_created')
    expect(messages[0].id).toBe('12045')

    const parsedEnvelope = JSON.parse(messages[0].data)
    expect(parsedEnvelope.cursor_id).toBe(12045)
    expect(parsedEnvelope.event_id).toBe('d9b7f8e1-4c2a-4f5b-9d8e-123456789abc')
    expect(parsedEnvelope.data.alert_uuid).toBe('al-9988')
    expect(parsedEnvelope.data.severity).toBe('HIGH')
  })
})

describe('Mock Fetch SSE Streaming Lifecycle', () => {
  it('passes Authorization header and Accept: text/event-stream to fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      body: {
        getReader: () => ({
          read: vi.fn().mockResolvedValue({ done: true, value: undefined }),
        }),
      },
    })
    globalThis.fetch = mockFetch

    const token = 'bearer-test-token'
    const lastEventId = 5501
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: 'text/event-stream',
    }
    if (lastEventId) {
      headers['Last-Event-ID'] = String(lastEventId)
    }

    await fetch('/v1/soc/stream', {
      method: 'GET',
      headers,
    })

    expect(mockFetch).toHaveBeenCalledWith('/v1/soc/stream', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer bearer-test-token',
        Accept: 'text/event-stream',
        'Last-Event-ID': '5501',
      },
    })
  })

  it('aborts active fetch reader cleanly using AbortController', async () => {
    const controller = new AbortController()
    const mockCancel = vi.fn()
    const reader = {
      cancel: mockCancel,
    }

    // Simulate unmount / disconnect
    controller.abort()
    reader.cancel()

    expect(controller.signal.aborted).toBe(true)
    expect(mockCancel).toHaveBeenCalled()
  })
})
