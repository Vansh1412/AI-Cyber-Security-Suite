import api from './api'
import type { ScanResult, HistoryItem, StatsResponse, HealthStatus, ExplainResult, FullReport } from '@/types'

export const scanService = {
  async scanUrl(url: string): Promise<ScanResult> {
    const res = await api.post('/v1/scan', { url })
    return res.data
  },

  async explainUrl(url: string): Promise<ExplainResult> {
    const res = await api.post('/v1/explain', { url })
    return res.data
  },

  async getReport(scanId: number): Promise<FullReport> {
    const res = await api.get(`/v2/report/${scanId}`)
    return res.data
  },

  async getHistory(page = 1, size = 20): Promise<HistoryItem[]> {
    const res = await api.get('/v1/history', { params: { page, size } })
    return res.data
  },

  async getStats(): Promise<StatsResponse> {
    const res = await api.get('/v1/stats')
    return res.data
  },

  async getHealth(): Promise<HealthStatus> {
    const res = await api.get('/v1/health')
    return res.data
  },

  async deleteHistoryItem(id: number): Promise<void> {
    await api.delete(`/v1/history/${id}`)
  },
}
