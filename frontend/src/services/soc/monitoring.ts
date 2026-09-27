/**
 * frontend/src/services/soc/monitoring.ts
 * ───────────────────────────────────────
 * Typed API client for Continuous Target Monitoring & Diagnostics.
 */

import api from '@/services/api'
import type {
  CheckNowResponse,
  MonitoringStatsResponse,
  MonitoringTarget,
  MonitoringTargetCreate,
  MonitoringTargetDiagnosticsResponse,
  MonitoringTargetListResponse,
  MonitoringTargetUpdate,
} from '@/types/soc'

export interface ListTargetsParams {
  page?: number
  page_size?: number
  include_inactive?: boolean
}

export const monitoringService = {
  async listTargets(params: ListTargetsParams = {}): Promise<MonitoringTargetListResponse> {
    const res = await api.get<MonitoringTargetListResponse>('/v1/monitor/targets', { params })
    return res.data
  },

  async getTarget(targetUuid: string): Promise<MonitoringTarget> {
    const res = await api.get<MonitoringTarget>(`/v1/monitor/targets/${targetUuid}`)
    return res.data
  },

  async registerTarget(payload: MonitoringTargetCreate): Promise<MonitoringTarget> {
    const res = await api.post<MonitoringTarget>('/v1/monitor/targets', payload)
    return res.data
  },

  async updateTarget(targetUuid: string, payload: MonitoringTargetUpdate): Promise<MonitoringTarget> {
    const res = await api.patch<MonitoringTarget>(`/v1/monitor/targets/${targetUuid}`, payload)
    return res.data
  },

  async deleteTarget(targetUuid: string): Promise<void> {
    await api.delete(`/v1/monitor/targets/${targetUuid}`)
  },

  async pauseTarget(targetUuid: string): Promise<MonitoringTarget> {
    const res = await api.post<MonitoringTarget>(`/v1/monitor/targets/${targetUuid}/pause`)
    return res.data
  },

  async resumeTarget(targetUuid: string): Promise<MonitoringTarget> {
    const res = await api.post<MonitoringTarget>(`/v1/monitor/targets/${targetUuid}/resume`)
    return res.data
  },

  async reactivateTarget(targetUuid: string): Promise<MonitoringTarget> {
    const res = await api.post<MonitoringTarget>(`/v1/monitor/targets/${targetUuid}/reactivate`)
    return res.data
  },

  async checkNow(targetUuid: string): Promise<CheckNowResponse> {
    const res = await api.post<CheckNowResponse>(`/v1/monitor/targets/${targetUuid}/check-now`)
    return res.data
  },

  async getDiagnostics(targetUuid: string): Promise<MonitoringTargetDiagnosticsResponse> {
    const res = await api.get<MonitoringTargetDiagnosticsResponse>(
      `/v1/monitor/targets/${targetUuid}/diagnostics`
    )
    return res.data
  },

  async getMonitoringStats(): Promise<MonitoringStatsResponse> {
    const res = await api.get<MonitoringStatsResponse>('/v1/monitor/stats')
    return res.data
  },
}
