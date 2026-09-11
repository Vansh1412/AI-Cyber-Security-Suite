// Shared TypeScript types for the entire application

export type PredictionClass = 'legitimate' | 'phishing' | 'malware' | 'defacement'

export interface User {
  id: number
  email: string
  role: 'user' | 'admin'
  is_active: boolean
}

export interface AuthTokens {
  access_token: string
  token_type: string
}

export interface ScanResult {
  url: string
  prediction: PredictionClass
  confidence: number
  latency_ms: number
  cache_hit: boolean
}

export interface ShapReason {
  feature: string
  value: number
  impact: number
  description?: string
}

export interface ExplainResult {
  url: string
  prediction: PredictionClass
  confidence: number
  top_reasons: ShapReason[]
  latency_ms: number
}

export interface HistoryItem {
  id: number
  url: string
  prediction: PredictionClass
  confidence: number
  latency_ms: number | null
  cache_hit: boolean
  top_reasons: ShapReason[] | null
  is_zero_day: boolean
  source_feed: string | null
  // Sprint 4 enrichment summary
  domain_age_days: number | null
  tls_valid: boolean | null
  redirect_count: number | null
  final_url: string | null
  created_at: string
}

export interface FullReport extends HistoryItem {
  threat_score: number
  model_env: string
}

export interface StatsResponse {
  total_scans: number
  by_class: Record<PredictionClass, number>
  daily_volume: { date: string; count: number }[]
}

export interface HealthStatus {
  status: 'healthy' | 'degraded'
  database: 'connected' | 'disconnected'
  redis: 'connected' | 'disconnected'
  model: 'loaded' | 'unloaded'
  version: string
  memory: string
}

export interface ApiError {
  detail: string
  status?: number
}

// ── Sprint 4: Threat Intelligence Enrichment ─────────────────────────────────

export interface TLSInfo {
  valid: boolean
  issuer: string | null
  subject: string | null
  expires_at: string | null
  days_to_expiry: number | null
  reason: string | null
}

export interface GeoLocation {
  ip: string | null
  city: string | null
  region: string | null
  country: string | null
  org: string | null
  private: boolean
}

export interface IntelEnrichment {
  scan_id: number
  url: string
  status?: 'pending' | 'completed' | 'failed' | 'blocked'
  domain_age_days: number | null
  tls_info: TLSInfo | null
  redirect_count: number
  final_url: string | null
  redirect_chain: string[]
  geolocation: GeoLocation | null
  enrichment_ms: number | null
}

export interface DeepScanFeature {
  name: string
  value: number
  category: 'lexical' | 'structural' | 'statistical' | 'keyword' | 'other'
}

export interface CanonicalFeatures {
  count: number // 59
  features: DeepScanFeature[]
}

export interface DeepScanReport {
  scan_id: number
  url: string
  prediction: PredictionClass
  confidence: number
  canonical_features?: CanonicalFeatures
  feature_vector: DeepScanFeature[]
  intel_enrichment: IntelEnrichment | null
  top_reasons: ShapReason[] | null
  created_at: string
}

// ── Sprint 4: Analytics ───────────────────────────────────────────────────────

export interface GlobalAnalytics {
  total_scans: number
  total_users: number
  by_class: Record<string, number>
  daily_volume: { date: string; count: number }[]
  zero_day_total: number
  zero_day_verified: number
  zero_day_promoted: number
  top_threat_domains: { domain: string; count: number; prediction: string }[]
  model_env: string
  active_model: string
}

export interface TrendPoint {
  date: string
  phishing: number
  malware: number
  defacement: number
  legitimate: number
  total: number
}

export interface TrendsData {
  window_days: number
  data: TrendPoint[]
}

export interface FeatureImportanceItem {
  feature: string
  avg_impact: number
  appearance_count: number
  category: string
}

export interface FeatureImportanceData {
  total_scans_analyzed: number
  features: FeatureImportanceItem[]
}

export interface PublicAnalytics {
  total_scans_platform: number
  threat_ratio: number
  by_class: Record<string, number>
}

// ── Sprint 4: Investigation ───────────────────────────────────────────────────

export interface BulkScanItem {
  url: string
  prediction: string | null
  confidence: number | null
  latency_ms: number | null
  error: string | null
}

export interface BulkScanResponse {
  total: number
  results: BulkScanItem[]
  elapsed_ms: number
}

export interface DomainScanHistory {
  domain: string
  total_scans: number
  threat_count: number
  latest_prediction: string | null
  latest_confidence: number | null
  scans: {
    id: number
    url: string
    prediction: string
    confidence: number
    created_at: string
    source_feed: string | null
  }[]
}
