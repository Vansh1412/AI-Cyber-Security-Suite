/**
 * frontend/src/__tests__/sse_parser.test.ts
 * ─────────────────────────────────────────
 * Unit tests for SSE frame parsing, backoff calculation, and event deduplication.
 */

import { describe, expect, it } from 'vitest'
import {
  calculateBackoff,
  isDuplicateEvent,
  parseSSEFrames,
} from '@/hooks/useSSEStream'

describe('parseSSEFrames', () => {
  it('correctly parses standard single SSE event frame', () => {
    const raw = 'event: alert_created\nid: 101\ndata: {"alert_uuid": "abc-123"}\n\n'
    const { messages, remainingBuffer } = parseSSEFrames(raw)

    expect(remainingBuffer).toBe('')
    expect(messages).toHaveLength(1)
    expect(messages[0]).toEqual({
      event: 'alert_created',
      id: '101',
      data: '{"alert_uuid": "abc-123"}',
    })
  })

  it('correctly parses multiple SSE frames in a single chunk', () => {
    const raw =
      'event: alert_created\nid: 1\ndata: {"n": 1}\n\n' +
      'event: alert_updated\nid: 2\ndata: {"n": 2}\n\n'
    const { messages, remainingBuffer } = parseSSEFrames(raw)

    expect(remainingBuffer).toBe('')
    expect(messages).toHaveLength(2)
    expect(messages[0].event).toBe('alert_created')
    expect(messages[0].id).toBe('1')
    expect(messages[1].event).toBe('alert_updated')
    expect(messages[1].id).toBe('2')
  })

  it('handles partial chunk buffering across stream reads', () => {
    const chunk1 = 'event: alert_created\nid: 105\ndata: {"status":'
    const result1 = parseSSEFrames(chunk1, '')

    expect(result1.messages).toHaveLength(0)
    expect(result1.remainingBuffer).toBe(chunk1)

    const chunk2 = ' "OPEN"}\n\n'
    const result2 = parseSSEFrames(chunk2, result1.remainingBuffer)

    expect(result2.messages).toHaveLength(1)
    expect(result2.messages[0]).toEqual({
      event: 'alert_created',
      id: '105',
      data: '{"status": "OPEN"}',
    })
    expect(result2.remainingBuffer).toBe('')
  })

  it('ignores heartbeat comment lines (: ping) without generating false domain events', () => {
    const raw = ': ping\n\n'
    const { messages, remainingBuffer } = parseSSEFrames(raw)

    expect(remainingBuffer).toBe('')
    expect(messages).toHaveLength(0)
  })

  it('ignores connection comments like : connected (pod_id: ...)', () => {
    const raw = ': connected (pod_id: pod-123)\n\n'
    const { messages } = parseSSEFrames(raw)
    expect(messages).toHaveLength(0)
  })

  it('correctly handles CRLF (\\r\\n\\r\\n) delimiters', () => {
    const raw = 'event: test_event\r\nid: 42\r\ndata: {"ok": true}\r\n\r\n'
    const { messages, remainingBuffer } = parseSSEFrames(raw)

    expect(remainingBuffer).toBe('')
    expect(messages).toHaveLength(1)
    expect(messages[0].id).toBe('42')
    expect(messages[0].event).toBe('test_event')
    expect(messages[0].data).toBe('{"ok": true}')
  })

  it('correctly stitches multi-line data payloads', () => {
    const raw =
      'event: multiline\nid: 99\ndata: {"part1": 1,\ndata: "part2": 2}\n\n'
    const { messages } = parseSSEFrames(raw)

    expect(messages).toHaveLength(1)
    expect(messages[0].data).toBe('{"part1": 1,\n"part2": 2}')
  })
})

describe('calculateBackoff', () => {
  it('implements exponential backoff: 1s, 2s, 4s, 8s, 16s', () => {
    expect(calculateBackoff(1, 30000, false)).toBe(1000)
    expect(calculateBackoff(2, 30000, false)).toBe(2000)
    expect(calculateBackoff(3, 30000, false)).toBe(4000)
    expect(calculateBackoff(4, 30000, false)).toBe(8000)
    expect(calculateBackoff(5, 30000, false)).toBe(16000)
  })

  it('strictly caps reconnect delay at maxDelayMs (30,000ms)', () => {
    expect(calculateBackoff(6, 30000, false)).toBe(30000)
    expect(calculateBackoff(10, 30000, false)).toBe(30000)
    expect(calculateBackoff(20, 30000, false)).toBe(30000)
  })

  it('adds jitter without exceeding max cap', () => {
    for (let attempt = 1; attempt <= 10; attempt++) {
      const delay = calculateBackoff(attempt, 30000, true)
      expect(delay).toBeGreaterThanOrEqual(1000)
      expect(delay).toBeLessThanOrEqual(30000)
    }
  })
})

describe('isDuplicateEvent', () => {
  it('identifies new event and remembers seen IDs', () => {
    const seen = new Set<string>()

    expect(isDuplicateEvent('evt-001', seen)).toBe(false)
    expect(seen.has('evt-001')).toBe(true)

    // Second occurrence is detected as duplicate
    expect(isDuplicateEvent('evt-001', seen)).toBe(true)
  })

  it('bounds memory by evicting oldest events when capacity exceeded', () => {
    const seen = new Set<string>()
    const maxCapacity = 5

    for (let i = 1; i <= 5; i++) {
      isDuplicateEvent(`evt-${i}`, seen, maxCapacity)
    }
    expect(seen.size).toBe(5)
    expect(seen.has('evt-1')).toBe(true)

    // Adding 6th element should evict the oldest ('evt-1')
    isDuplicateEvent('evt-6', seen, maxCapacity)
    expect(seen.size).toBe(5)
    expect(seen.has('evt-1')).toBe(false)
    expect(seen.has('evt-6')).toBe(true)
  })
})
