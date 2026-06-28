// utils/cache.ts — chrome.storage.local with TTL

import type { CachedEntry, ScanResult, ExplainResult } from '../types/index.js'

const CACHE_PREFIX = 'scan_cache_'
const DEFAULT_TTL_HOURS = 24
const MS_PER_HOUR = 3_600_000

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url)
    // Strip fragment, normalize trailing slash
    return `${u.protocol}//${u.host}${u.pathname}${u.search}`.replace(/\/$/, '')
  } catch {
    return url
  }
}

function cacheKey(url: string): string {
  return CACHE_PREFIX + normalizeUrl(url)
}

/**
 * Retrieve a cached scan result. Returns null if missing or expired.
 */
export async function cacheGet(url: string): Promise<CachedEntry | null> {
  const key = cacheKey(url)
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (result) => {
      if (chrome.runtime.lastError) {
        resolve(null)
        return
      }
      const entry = result[key] as CachedEntry | undefined
      if (!entry) {
        resolve(null)
        return
      }
      // Check TTL
      if (Date.now() > entry.expires_at) {
        chrome.storage.local.remove(key)
        resolve(null)
        return
      }
      resolve(entry)
    })
  })
}

/**
 * Store a scan result with TTL.
 */
export async function cacheSet(
  url: string,
  scan: ScanResult,
  ttlHours: number = DEFAULT_TTL_HOURS
): Promise<void> {
  const key = cacheKey(url)
  const now = Date.now()
  const entry: CachedEntry = {
    scan,
    cached_at: now,
    expires_at: now + ttlHours * MS_PER_HOUR,
  }
  return new Promise((resolve) => {
    chrome.storage.local.set({ [key]: entry }, () => resolve())
  })
}

/**
 * Update an existing cache entry with SHAP explanation data.
 */
export async function cacheSetExplain(url: string, explain: ExplainResult): Promise<void> {
  const key = cacheKey(url)
  return new Promise((resolve) => {
    chrome.storage.local.get(key, (result) => {
      const entry = result[key] as CachedEntry | undefined
      if (entry) {
        entry.explain = explain
        chrome.storage.local.set({ [key]: entry }, () => resolve())
      } else {
        resolve()
      }
    })
  })
}

/**
 * Remove a specific URL from cache (for manual rescan).
 */
export async function cacheClear(url: string): Promise<void> {
  const key = cacheKey(url)
  return new Promise((resolve) => {
    chrome.storage.local.remove(key, () => resolve())
  })
}

/**
 * Clear all scan cache entries.
 */
export async function cacheClearAll(): Promise<void> {
  return new Promise((resolve) => {
    chrome.storage.local.get(null, (items) => {
      const keysToRemove = Object.keys(items).filter((k) => k.startsWith(CACHE_PREFIX))
      if (keysToRemove.length === 0) {
        resolve()
        return
      }
      chrome.storage.local.remove(keysToRemove, () => resolve())
    })
  })
}

/**
 * Get auth token from storage.
 */
export async function getAuthToken(): Promise<string | null> {
  return new Promise((resolve) => {
    chrome.storage.local.get('auth_token', (result) => {
      resolve((result['auth_token'] as string) || null)
    })
  })
}

/**
 * Get API base URL from storage, falling back to localhost.
 */
export async function getApiBase(): Promise<string> {
  return new Promise((resolve) => {
    chrome.storage.local.get('api_base', (result) => {
      resolve((result['api_base'] as string) || 'http://localhost:8000')
    })
  })
}
