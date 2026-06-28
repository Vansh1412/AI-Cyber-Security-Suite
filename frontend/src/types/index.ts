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

export interface FullReport {
  id: number
  url: string
  prediction: PredictionClass
  confidence: number
  latency_ms: number | null
  cache_hit: boolean
  top_reasons: ShapReason[] | null
  threat_score: number
  model_env: string
  created_at: string
}

export interface HistoryItem {
  id: number
  url: string
  prediction: PredictionClass
  confidence: number
  latency_ms: number | null
  cache_hit: boolean
  top_reasons: ShapReason[] | null
  created_at: string
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
