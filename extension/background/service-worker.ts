// background/service-worker.ts
// ─────────────────────────────────────────────────────────────────────────────
// The core MV3 service worker.
// Listens to tab updates → checks cache → calls /v2/scan → updates badge.
// Fires /v1/explain asynchronously to enrich the cached entry with SHAP data.
// Handles offline mode, notifications, and context menu.
// ─────────────────────────────────────────────────────────────────────────────

import { cacheGet, cacheSet, cacheSetExplain, cacheClear, getAuthToken, getApiBase } from '../utils/cache.js'
import { setBadge, clearBadge, predictionToMode, computeThreatScore } from '../utils/badge.js'
import { scanUrl, explainUrl, checkHealth, ApiError } from '../services/api.js'
import type { ScanResult, ExplainResult } from '../types/index.js'

// ── Constants ──────────────────────────────────────────────────────────────
const NOTIFICATION_THRESHOLD = 0.92
const CONTEXT_MENU_SCAN_PAGE = 'analyze_page'
const CONTEXT_MENU_SCAN_LINK = 'analyze_link'
const HEALTH_ALARM_NAME = 'health_check'

// ── Helpers ────────────────────────────────────────────────────────────────

/** Returns true if the URL should be scanned (skip internal browser pages). */
function shouldScan(url: string): boolean {
  if (!url) return false
  const skip = ['chrome://', 'chrome-extension://', 'edge://', 'about:', 'file://', 'data:']
  return !skip.some(prefix => url.startsWith(prefix))
}

/** Write the current scan result to storage so the popup can read it. */
async function setCurrentScan(url: string, scan: ScanResult | null, explain?: ExplainResult | null): Promise<void> {
  await chrome.storage.local.set({
    current_url: url,
    current_scan: scan,
    current_explain: explain ?? null,
  })
}

/** Show a Chrome notification for high-confidence threats. */
function maybeNotify(scan: ScanResult): void {
  if (
    scan.prediction !== 'legitimate' &&
    scan.confidence >= NOTIFICATION_THRESHOLD
  ) {
    const threatLabel = scan.prediction.charAt(0).toUpperCase() + scan.prediction.slice(1)
    try {
      new URL(scan.url)
      const domain = new URL(scan.url).hostname
      chrome.notifications.create(`threat_${Date.now()}`, {
        type: 'basic',
        iconUrl: '../assets/icon48.png',
        title: `⚠️ ${threatLabel} Detected`,
        message: `${domain} has been flagged as ${scan.prediction} (${(scan.confidence * 100).toFixed(1)}% confidence). Avoid entering credentials.`,
        priority: 2,
      })
    } catch { /* ignore malformed URLs */ }
  }
}

// ── Core Scan Flow ─────────────────────────────────────────────────────────

const inFlight = new Set<string>()

async function handleTabScan(tabId: number, url: string): Promise<void> {
  if (inFlight.has(url)) return
  inFlight.add(url)
  
  try {
    // 1. Set "loading" badge immediately
    await setBadge(tabId, 'loading')

  const [token, apiBase] = await Promise.all([getAuthToken(), getApiBase()])

  // 2. Check local cache first (< 5ms path)
  const cached = await cacheGet(url)
  if (cached) {
    const mode = predictionToMode(cached.scan.prediction)
    await setBadge(tabId, mode)
    await setCurrentScan(url, cached.scan, cached.explain ?? null)
    return
  }

  // 3. Cache miss → call the API
  let scan: ScanResult
  try {
    scan = await scanUrl(url, apiBase, token)
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      // Token expired — clear it
      await chrome.storage.local.remove('auth_token')
    }
    // Check if backend is just unreachable or failed
    const healthy = await checkHealth(apiBase)
    await setBadge(tabId, healthy ? 'error' : 'offline')
    
    // Clear current_url so the popup knows to show the offline/error state
    // instead of being stuck in the "Scanning website..." UI forever.
    await chrome.storage.local.set({
      current_url: null,
      current_scan: null,
      current_explain: null,
    })
    return
  }

  // 4. Update badge immediately based on scan result
  const mode = predictionToMode(scan.prediction)
  await setBadge(tabId, mode)

  // 5. Cache the scan result (SHAP comes later)
  await cacheSet(url, scan)
  await setCurrentScan(url, scan, null)

  // 6. Show notification for high-confidence threats
  maybeNotify(scan)

  // 7. Fire SHAP explanation asynchronously — do NOT await
  explainUrl(url, apiBase, token)
    .then(async (explain) => {
      await cacheSetExplain(url, explain)
      // Update popup if it's still on the same URL
      const stored = await chrome.storage.local.get('current_url')
      if (stored['current_url'] === url) {
        await setCurrentScan(url, scan, explain)
      }
    })
    .catch(() => { /* SHAP failure is silent — badge already set */ })
  } finally {
    inFlight.delete(url)
  }
}

// ── Tab Listeners ─────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return
  const url = tab.url ?? changeInfo.url ?? ''
  if (!shouldScan(url)) {
    clearBadge(tabId)
    return
  }
  handleTabScan(tabId, url)
})

// When user switches tabs, restore the badge from cache
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null)
  if (!tab?.url || !shouldScan(tab.url)) {
    if (tab?.id) clearBadge(tab.id)
    return
  }
  const cached = await cacheGet(tab.url)
  if (cached) {
    await setBadge(tabId, predictionToMode(cached.scan.prediction))
    await setCurrentScan(tab.url, cached.scan, cached.explain ?? null)
  } else {
    await setBadge(tabId, 'loading')
    await setCurrentScan(tab.url, null)
    // Trigger scan for the newly activated tab
    handleTabScan(tabId, tab.url)
  }
})

// ── Context Menu ──────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: CONTEXT_MENU_SCAN_PAGE,
    title: 'Analyze Current Page',
    contexts: ['page'],
  })
  chrome.contextMenus.create({
    id: CONTEXT_MENU_SCAN_LINK,
    title: 'Analyze This Link',
    contexts: ['link'],
  })

  // Health-check alarm: every 5 minutes
  chrome.alarms.create(HEALTH_ALARM_NAME, { periodInMinutes: 5 })
})

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.menuItemId === CONTEXT_MENU_SCAN_LINK
    ? info.linkUrl
    : info.pageUrl ?? tab?.url

  if (!url || !tab?.id) return

  // Force rescan by clearing cache first
  await cacheClear(url)
  if (info.menuItemId === CONTEXT_MENU_SCAN_PAGE) {
    await handleTabScan(tab.id, url)
  } else {
    // For link analysis: store target URL, then open popup
    await chrome.storage.local.set({ context_menu_url: url, current_url: url, current_scan: null })
    // Trigger background scan for the link URL (no tab ID needed for badge)
    const [token, apiBase] = await Promise.all([getAuthToken(), getApiBase()])
    scanUrl(url, apiBase, token)
      .then(async (scan) => {
        await cacheSet(url, scan)
        await chrome.storage.local.set({ current_url: url, current_scan: scan })
      })
      .catch(async () => {
        await chrome.storage.local.set({
          current_url: null,
          current_scan: null,
          current_explain: null,
        })
      })
  }
})

// ── Alarm Handler (Periodic Health Check) ────────────────────────────────

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== HEALTH_ALARM_NAME) return
  const apiBase = await getApiBase()
  const healthy = await checkHealth(apiBase)
  if (!healthy) {
    // Mark all active tabs as offline
    const tabs = await chrome.tabs.query({ active: true })
    for (const tab of tabs) {
      if (tab.id && tab.url && shouldScan(tab.url)) {
        await setBadge(tab.id, 'offline')
      }
    }
  }
})

// ── Message Handler (from popup: rescan) ─────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'RESCAN') {
    const { url, tabId } = message
    if (!url || !tabId) { sendResponse({ ok: false }); return true }
    cacheClear(url).then(() => {
      handleTabScan(tabId, url)
      sendResponse({ ok: true })
    })
    return true // keep message channel open for async
  }

  if (message.type === 'GET_CURRENT') {
    chrome.storage.local.get(['current_url', 'current_scan', 'current_explain'], (result) => {
      sendResponse(result)
    })
    return true
  }

  if (message.type === 'SET_API_BASE') {
    chrome.storage.local.set({ api_base: message.apiBase }, () => sendResponse({ ok: true }))
    return true
  }
})
