import api from './api'
import type {
  ScanResult,
  HistoryItem,
  FullReport,
  StatsResponse,
  HealthStatus,
  ExplainResult,
  IntelEnrichment,
  DeepScanReport,
  BulkScanResponse,
  DomainScanHistory,
  GlobalAnalytics,
  TrendsData,
  FeatureImportanceData,
  PublicAnalytics,
} from '@/types'

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
    const res = await api.get(`/v1/history/${scanId}`)
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

  // ── Sprint 4: Intel Enrichment ───────────────────────────────────────────

  async triggerEnrichment(scanId: number): Promise<IntelEnrichment> {
    const res = await api.post(`/v1/intel/${scanId}/enrich`)
    return res.data
  },

  async getIntelEnrichment(scanId: number): Promise<IntelEnrichment> {
    const res = await api.get(`/v1/intel/${scanId}`)
    return res.data
  },

  async getDeepReport(scanId: number): Promise<DeepScanReport> {
    const res = await api.get(`/v1/scan/${scanId}/deep-report`)
    return res.data
  },

  // ── Sprint 4: Investigation ──────────────────────────────────────────────

  async bulkScan(urls: string[]): Promise<BulkScanResponse> {
    const res = await api.post('/v1/investigate/bulk', { urls })
    return res.data
  },

  async getDomainHistory(domain: string): Promise<DomainScanHistory> {
    const res = await api.get(`/v1/investigate/domain/${encodeURIComponent(domain)}`)
    return res.data
  },

  // ── Sprint 4: Analytics ──────────────────────────────────────────────────

  async getGlobalAnalytics(): Promise<GlobalAnalytics> {
    const res = await api.get('/v1/analytics/global')
    return res.data
  },

  async getPublicAnalytics(): Promise<PublicAnalytics> {
    const res = await api.get('/v1/analytics/public')
    return res.data
  },

  async getTrends(windowDays = 30): Promise<TrendsData> {
    const res = await api.get('/v1/analytics/trends', { params: { window_days: windowDays } })
    return res.data
  },

  async getFeatureImportance(limit = 20): Promise<FeatureImportanceData> {
    const res = await api.get('/v1/analytics/feature-importance', { params: { limit } })
    return res.data
  },
}
