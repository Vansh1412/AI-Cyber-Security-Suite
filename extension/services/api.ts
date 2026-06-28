// services/api.ts — API wrappers for the AI Cyber Security backend

import type { ScanResult, ExplainResult } from '../types/index.js'

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

/**
 * Scan a URL — POST /v2/scan
 * Works with or without a token (anonymous scans are not persisted).
 */
export async function scanUrl(
  url: string,
  apiBase: string,
  token: string | null
): Promise<ScanResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${apiBase}/v1/scan`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(15_000),
  })

  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new ApiError(res.status, `Scan failed: ${res.status} ${body}`)
  }

  const data = await res.json()
  return {
    url: data.url ?? url,
    prediction: data.prediction,
    confidence: data.confidence,
    latency_ms: data.latency_ms ?? 0,
    cache_hit: data.cache_hit ?? false,
    scan_id: data.id ?? data.scan_id,
  }
}

/**
 * Explain a URL — POST /v1/explain
 * Returns SHAP feature attributions.
 */
export async function explainUrl(
  url: string,
  apiBase: string,
  token: string | null
): Promise<ExplainResult> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${apiBase}/v1/explain`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(20_000),
  })

  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new ApiError(res.status, `Explain failed: ${res.status} ${body}`)
  }

  return res.json()
}

/**
 * Health check — GET /v1/health
 * Returns true if the backend is reachable and healthy.
 */
export async function checkHealth(apiBase: string): Promise<boolean> {
  try {
    const res = await fetch(`${apiBase}/v1/health`, {
      signal: AbortSignal.timeout(5_000),
    })
    return res.ok
  } catch {
    return false
  }
}
