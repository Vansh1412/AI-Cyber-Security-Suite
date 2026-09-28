/**
 * frontend/src/hooks/useSSEStream.ts
 * ──────────────────────────────────
 * Production-grade Server-Sent Events (SSE) streaming hook using fetch + ReadableStream.
 *
 * Security & Reliability Guarantees:
 * - Direct 'Authorization: Bearer <token>' header authentication.
 * - Zero reusable JWT tokens in URLs or query strings.
 * - Monotonic Last-Event-ID tracking and replay propagation.
 * - Jittered exponential backoff reconnects capped at 30 seconds.
 * - Robust handling of server control frames:
 *     • heartbeat (: ping)
 *     • stream_reset (cursor expired -> triggers cache resync)
 *     • stream_refresh (1-hour max lifetime reached -> seamless reconnect)
 *     • stream_overflow (queue saturated -> reconnect from replay cursor)
 *     • stream_auth_revoked (account revoked -> session termination)
 *     • server_shutdown (graceful pod exit -> reconnect after server delay)
 * - Complete teardown and abort controller cancellation on unmount.
 * - Message deduplication across recent events.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type {
  SSEEventEnvelope,
  StreamConnectionStatus,
  StreamControlFrame,
} from '@/types/soc'
import { streamsService } from '@/services/soc/streams'

// ── Pure Helper Functions (Exported for Unit Testing) ──────────────────────────

export interface ParsedSSEMessage {
  event: string
  id: string | null
  data: string
}

/**
 * Calculates jittered exponential backoff in milliseconds.
 * Sequence: ~1s, 2s, 4s, 8s, 16s... capped at maxDelayMs (default 30,000ms).
 */
export function calculateBackoff(
  attempt: number,
  maxDelayMs: number = 30000,
  jitter: boolean = true
): number {
  const base = Math.min(maxDelayMs, 1000 * Math.pow(2, Math.max(0, attempt - 1)))
  if (!jitter) return base
  const randomJitter = Math.floor(Math.random() * 500)
  return Math.min(maxDelayMs, base + randomJitter)
}

/**
 * Parses raw SSE chunk stream data into structured messages and unconsumed buffer.
 * Supports standard \n\n and \r\n\r\n frame delimiters and comment lines (: ping).
 */
export function parseSSEFrames(
  incomingChunk: string,
  buffer: string = ''
): { messages: ParsedSSEMessage[]; remainingBuffer: string } {
  const combined = buffer + incomingChunk
  const messages: ParsedSSEMessage[] = []

  // Normalise \r\n to \n
  const normalized = combined.replace(/\r\n/g, '\n')
  const rawFrames = normalized.split('\n\n')

  // The last element is either empty (if ended with \n\n) or an incomplete frame
  const remainingBuffer = rawFrames.pop() ?? ''

  for (const frame of rawFrames) {
    const trimmed = frame.trim()
    if (!trimmed) continue

    let event = 'message'
    let id: string | null = null
    const dataLines: string[] = []

    const lines = trimmed.split('\n')
    for (const line of lines) {
      if (line.startsWith(':')) {
        // Comment or heartbeat frame (e.g. ": ping")
        continue
      }
      if (line.startsWith('event:')) {
        event = line.slice(6).trim()
      } else if (line.startsWith('id:')) {
        id = line.slice(3).trim()
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trim())
      }
    }

    if (dataLines.length > 0 || event !== 'message') {
      messages.push({
        event,
        id,
        data: dataLines.join('\n'),
      })
    }
  }

  return { messages, remainingBuffer }
}

/**
 * Evaluates whether an event ID has already been processed to prevent duplication.
 */
export function isDuplicateEvent(
  eventId: string,
  seenSet: Set<string>,
  maxHistory: number = 200
): boolean {
  if (seenSet.has(eventId)) {
    return true
  }
  seenSet.add(eventId)
  if (seenSet.size > maxHistory) {
    const oldest = seenSet.values().next().value
    if (oldest) seenSet.delete(oldest)
  }
  return false
}

// ── Hook Definition ──────────────────────────────────────────────────────────

export interface UseSSEStreamOptions {
  channel?: 'soc' | 'alerts' | 'notifications' | 'admin'
  minSeverity?: string
  autoConnect?: boolean
  autoInvalidateQueryKeys?: boolean
  onEvent?: (envelope: SSEEventEnvelope) => void
  onResyncRequired?: () => void
  onAuthRevoked?: (reason: string) => void
}

export interface UseSSEStreamReturn {
  status: StreamConnectionStatus
  lastEventId: number | null
  reconnectAttempt: number
  lastEvent: SSEEventEnvelope | null
  error: string | null
  connect: () => void
  disconnect: () => void
}

export function useSSEStream(options: UseSSEStreamOptions = {}): UseSSEStreamReturn {
  const {
    channel = 'soc',
    minSeverity,
    autoConnect = true,
    autoInvalidateQueryKeys = true,
    onEvent,
    onResyncRequired,
    onAuthRevoked,
  } = options

  const [status, setStatus] = useState<StreamConnectionStatus>('disconnected')
  const [lastEventId, setLastEventId] = useState<number | null>(null)
  const [reconnectAttempt, setReconnectAttempt] = useState<number>(0)
  const [lastEvent, setLastEvent] = useState<SSEEventEnvelope | null>(null)
  const [error, setError] = useState<string | null>(null)

  const queryClient = useQueryClient()
  const abortControllerRef = useRef<AbortController | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const seenEventIdsRef = useRef<Set<string>>(new Set())
  const isIntentionalDisconnectRef = useRef<boolean>(false)
  const activeConnectionRef = useRef<boolean>(false)
  const lastEventIdRef = useRef<number | null>(null)

  // Keep ref synchronized for reconnect header inclusion
  useEffect(() => {
    lastEventIdRef.current = lastEventId
  }, [lastEventId])

  // Invalidate relevant React Query keys on inbound domain events
  const handleQueryCacheInvalidation = useCallback(
    (eventType: string) => {
      if (!autoInvalidateQueryKeys) return

      if (eventType.startsWith('alert_')) {
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
        queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
        queryClient.invalidateQueries({ queryKey: ['incidents'] })
      } else if (eventType.startsWith('notification_')) {
        queryClient.invalidateQueries({ queryKey: ['notifications'] })
        queryClient.invalidateQueries({ queryKey: ['notifications-unread'] })
      } else if (eventType.startsWith('target_')) {
        queryClient.invalidateQueries({ queryKey: ['monitoring-targets'] })
        queryClient.invalidateQueries({ queryKey: ['monitoring-stats'] })
      } else if (eventType.startsWith('containment_') || eventType.startsWith('playbook_')) {
        queryClient.invalidateQueries({ queryKey: ['containment-actions'] })
        queryClient.invalidateQueries({ queryKey: ['playbook-runs'] })
      }
    },
    [autoInvalidateQueryKeys, queryClient]
  )

  const cleanupConnection = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }
    activeConnectionRef.current = false
  }, [])

  const disconnect = useCallback(() => {
    isIntentionalDisconnectRef.current = true
    cleanupConnection()
    setStatus('disconnected')
    setError(null)
  }, [cleanupConnection])

  const connect = useCallback(async () => {
    // Prevent overlapping parallel connections
    if (activeConnectionRef.current) {
      return
    }

    cleanupConnection()
    isIntentionalDisconnectRef.current = false

    const token = streamsService.getBearerToken()
    if (!token) {
      setStatus('disconnected')
      setError('Missing authentication token')
      return
    }

    const abortController = new AbortController()
    abortControllerRef.current = abortController
    activeConnectionRef.current = true

    setStatus((prev) => (prev === 'disconnected' ? 'connecting' : 'reconnecting'))
    setError(null)

    const streamPath = streamsService.buildStreamPath(channel, minSeverity)

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: 'text/event-stream',
    }

    if (lastEventIdRef.current !== null && lastEventIdRef.current !== undefined) {
      headers['Last-Event-ID'] = String(lastEventIdRef.current)
    }

    try {
      const response = await fetch(streamPath, {
        method: 'GET',
        headers,
        signal: abortController.signal,
      })

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          setStatus('auth_revoked')
          setError(`Stream authorization rejected (HTTP ${response.status})`)
          activeConnectionRef.current = false
          onAuthRevoked?.(`HTTP ${response.status}`)
          return
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      if (!response.body) {
        throw new Error('ReadableStream not supported by response body')
      }

      // Connection established successfully
      setStatus('connected')
      setReconnectAttempt(0)
      setError(null)

      const reader = response.body.getReader()
      const decoder = new TextDecoder('utf-8')
      let streamBuffer = ''

      while (activeConnectionRef.current && !abortController.signal.aborted) {
        const { value, done } = await reader.read()
        if (done) break

        const chunkText = decoder.decode(value, { stream: true })
        const { messages, remainingBuffer } = parseSSEFrames(chunkText, streamBuffer)
        streamBuffer = remainingBuffer

        for (const msg of messages) {
          // Parse cursor ID if present
          if (msg.id) {
            const parsedCursor = parseInt(msg.id, 10)
            if (!isNaN(parsedCursor)) {
              setLastEventId(parsedCursor)
              lastEventIdRef.current = parsedCursor
            }
          }

          // Handle special server control frames
          if (msg.event === 'stream_reset') {
            try {
              const frame: StreamControlFrame = JSON.parse(msg.data)
              if (frame.action === 'resync_required') {
                onResyncRequired?.()
                queryClient.invalidateQueries()
              }
            } catch {
              onResyncRequired?.()
            }
            continue
          }

          if (msg.event === 'stream_refresh') {
            // Seamless max-lifetime reconnect without showing error banner
            cleanupConnection()
            connect()
            return
          }

          if (msg.event === 'stream_overflow') {
            try {
              const frame: StreamControlFrame = JSON.parse(msg.data)
              if (frame.last_delivered_id) {
                setLastEventId(frame.last_delivered_id)
                lastEventIdRef.current = frame.last_delivered_id
              }
            } catch { /* proceed with last known cursor */ }
            cleanupConnection()
            connect()
            return
          }

          if (msg.event === 'stream_auth_revoked') {
            setStatus('auth_revoked')
            setError('Stream authentication was revoked by server')
            cleanupConnection()
            onAuthRevoked?.(msg.data)
            return
          }

          if (msg.event === 'server_shutdown') {
            let backoffSec = 5
            try {
              const frame: StreamControlFrame = JSON.parse(msg.data)
              if (frame.reconnect_after) backoffSec = frame.reconnect_after
            } catch { /* use default 5s */ }
            cleanupConnection()
            setStatus('reconnecting')
            reconnectTimeoutRef.current = setTimeout(connect, backoffSec * 1000)
            return
          }

          // Domain event payload parsing
          if (msg.data) {
            try {
              const envelope: SSEEventEnvelope = JSON.parse(msg.data)

              // Deduplicate events by unique UUID
              if (envelope.event_id && isDuplicateEvent(envelope.event_id, seenEventIdsRef.current)) {
                continue
              }

              if (envelope.cursor_id !== undefined && envelope.cursor_id !== null) {
                setLastEventId(envelope.cursor_id)
                lastEventIdRef.current = envelope.cursor_id
              }

              setLastEvent(envelope)
              onEvent?.(envelope)
              handleQueryCacheInvalidation(envelope.event_type)
            } catch {
              // Non-JSON domain message — safely ignored
            }
          }
        }
      }
    } catch (err: unknown) {
      const errorObj = err instanceof Error ? err : new Error(String(err))
      if (errorObj.name === 'AbortError' || isIntentionalDisconnectRef.current) {
        // Normal teardown
        return
      }

      activeConnectionRef.current = false
      setStatus('reconnecting')
      setError(errorObj.message || 'Stream connection error')

      // Schedule jittered exponential reconnect
      setReconnectAttempt((prev) => {
        const nextAttempt = prev + 1
        const delay = calculateBackoff(nextAttempt)
        reconnectTimeoutRef.current = setTimeout(connect, delay)
        return nextAttempt
      })
    }
  }, [
    channel,
    cleanupConnection,
    handleQueryCacheInvalidation,
    minSeverity,
    onAuthRevoked,
    onEvent,
    onResyncRequired,
    queryClient,
  ])

  // Lifecycle: connect on mount if autoConnect is enabled, clean up on unmount
  useEffect(() => {
    if (autoConnect) {
      connect()
    }
    return () => {
      cleanupConnection()
    }
  }, [autoConnect, cleanupConnection, connect])

  return {
    status,
    lastEventId,
    reconnectAttempt,
    lastEvent,
    error,
    connect,
    disconnect,
  }
}
