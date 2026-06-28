// types/index.ts — Shared interfaces for the extension

export type PredictionClass = 'legitimate' | 'phishing' | 'malware' | 'defacement'

export interface ScanResult {
  url: string
  prediction: PredictionClass
  confidence: number
  latency_ms: number
  cache_hit: boolean
  scan_id?: number
  threat_score?: number
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

export interface CachedEntry {
  scan: ScanResult
  explain?: ExplainResult
  cached_at: number   // Date.now()
  expires_at: number  // cached_at + TTL_MS
}

export interface StorageState {
  [key: string]: unknown
  auth_token?: string
  api_base?: string
  current_scan?: ScanResult | null
  current_explain?: ExplainResult | null
  current_url?: string
}

export interface BadgeState {
  color: string
  text: string
  title: string
}
