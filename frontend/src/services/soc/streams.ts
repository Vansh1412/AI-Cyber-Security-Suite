/**
 * frontend/src/services/soc/streams.ts
 * ────────────────────────────────────
 * Typed API client and helpers for the Real-Time SSE Streaming Gateway.
 *
 * Security:
 * - Never place reusable JWT tokens in query parameters (?token=...).
 * - Streams are accessed via fetch + ReadableStream using the 'Authorization: Bearer <token>' header,
 *   OR via short-lived 30s single-use stream tickets (POST /v1/streams/ticket).
 */

import api from '@/services/api'
import type { StreamTicketResponse } from '@/types/soc'

export const streamsService = {
  /**
   * Exchange Bearer JWT for a single-use 30-second stream ticket.
   */
  async createTicket(channel: string = 'soc'): Promise<StreamTicketResponse> {
    const res = await api.post<StreamTicketResponse>('/v1/streams/ticket', { channel })
    return res.data
  },

  /**
   * Return the active Bearer token for request header authentication.
   * Does NOT log or leak the token.
   */
  getBearerToken(): string | null {
    return localStorage.getItem('access_token')
  },

  /**
   * Build the relative stream path for the unified SOC stream.
   * Query parameters are restricted to non-sensitive filters (e.g. min_severity).
   * JWT tokens are NEVER appended to the URL.
   */
  buildStreamPath(channel: 'soc' | 'alerts' | 'notifications' | 'admin' = 'soc', minSeverity?: string): string {
    const basePath = channel === 'admin'
      ? '/v1/admin/soc/stream'
      : channel === 'alerts'
      ? '/v1/alerts/stream'
      : channel === 'notifications'
      ? '/v1/notifications/stream'
      : '/v1/soc/stream'

    if (minSeverity) {
      const sp = new URLSearchParams()
      sp.set('min_severity', minSeverity)
      return `${basePath}?${sp.toString()}`
    }

    return basePath
  },
}
