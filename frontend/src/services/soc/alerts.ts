/**
 * frontend/src/services/soc/alerts.ts
 * ───────────────────────────────────
 * Typed API client for Security Alerts and Triage Management.
 */

import api from '@/services/api'
import type {
  Alert,
  AlertAcknowledgeRequest,
  AlertDismissRequest,
  AlertListResponse,
  AlertReopenRequest,
  AlertResolveRequest,
  AlertStatsResponse,
} from '@/types/soc'

export interface ListAlertsParams {
  page?: number
  page_size?: number
  severity?: string
  status?: string
  rule_name?: string
  indicator_type?: string
  incident_id?: number
}

export const alertsService = {
  async listAlerts(params: ListAlertsParams = {}): Promise<AlertListResponse> {
    const res = await api.get<AlertListResponse>('/v1/alerts', { params })
    return res.data
  },

  async getAlertStats(): Promise<AlertStatsResponse> {
    const res = await api.get<AlertStatsResponse>('/v1/alerts/stats')
    return res.data
  },

  async getAlert(alertUuid: string): Promise<Alert> {
    const res = await api.get<Alert>(`/v1/alerts/${alertUuid}`)
    return res.data
  },

  async acknowledgeAlert(alertUuid: string, payload?: AlertAcknowledgeRequest): Promise<Alert> {
    const res = await api.post<Alert>(`/v1/alerts/${alertUuid}/acknowledge`, payload)
    return res.data
  },

  async resolveAlert(alertUuid: string, payload?: AlertResolveRequest): Promise<Alert> {
    const res = await api.post<Alert>(`/v1/alerts/${alertUuid}/resolve`, payload)
    return res.data
  },

  async dismissAlert(alertUuid: string, payload: AlertDismissRequest): Promise<Alert> {
    const res = await api.post<Alert>(`/v1/alerts/${alertUuid}/dismiss`, payload)
    return res.data
  },

  async reopenAlert(alertUuid: string, payload?: AlertReopenRequest): Promise<Alert> {
    const res = await api.post<Alert>(`/v1/alerts/${alertUuid}/reopen`, payload)
    return res.data
  },
}
