/**
 * frontend/src/services/soc/incidents.ts
 * ──────────────────────────────────────
 * Typed API client for Security Incidents Management.
 */

import api from '@/services/api'
import type {
  Alert,
  AttachAlertsRequest,
  Incident,
  IncidentCreate,
  IncidentStatus,
  IncidentUpdate,
} from '@/types/soc'

export interface ListIncidentsParams {
  status?: IncidentStatus | string
  severity?: string
  page?: number
  size?: number
}

export const incidentsService = {
  async listIncidents(params: ListIncidentsParams = {}): Promise<Incident[]> {
    const res = await api.get<Incident[]>('/v1/incidents', { params })
    return res.data
  },

  async getIncident(incidentIdOrUuid: string | number): Promise<Incident> {
    const res = await api.get<Incident>(`/v1/incidents/${incidentIdOrUuid}`)
    return res.data
  },

  async createIncident(payload: IncidentCreate): Promise<Incident> {
    const res = await api.post<Incident>('/v1/incidents', payload)
    return res.data
  },

  async updateIncident(
    incidentIdOrUuid: string | number,
    payload: IncidentUpdate
  ): Promise<Incident> {
    const res = await api.patch<Incident>(`/v1/incidents/${incidentIdOrUuid}`, payload)
    return res.data
  },

  async attachAlerts(
    incidentIdOrUuid: string | number,
    payload: AttachAlertsRequest
  ): Promise<Incident> {
    const res = await api.post<Incident>(`/v1/incidents/${incidentIdOrUuid}/alerts`, payload)
    return res.data
  },

  async detachAlert(
    incidentIdOrUuid: string | number,
    alertId: number
  ): Promise<Incident> {
    const res = await api.delete<Incident>(`/v1/incidents/${incidentIdOrUuid}/alerts/${alertId}`)
    return res.data
  },

  async getIncidentAlerts(incidentIdOrUuid: string | number): Promise<Alert[]> {
    const res = await api.get<Alert[]>(`/v1/incidents/${incidentIdOrUuid}/alerts`)
    return res.data
  },
}
