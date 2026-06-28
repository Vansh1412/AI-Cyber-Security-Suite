// popup/popup.ts
// ─────────────────────────────────────────────────────────────────────────────
// Reads the current scan state from chrome.storage.local and renders the UI.
// Listens for storage changes so the popup updates live when SHAP arrives.
// ─────────────────────────────────────────────────────────────────────────────

import type { ScanResult, ExplainResult, PredictionClass } from '../types/index.js'

// ── DOM refs ──────────────────────────────────────────────────────────────
// ── DOM refs ──────────────────────────────────────────────────────────────
const $el = (id: string) => document.getElementById(id) as HTMLElement
const $svg = (id: string) => document.getElementById(id) as unknown as SVGCircleElement

const headerDomain     = $el('header-domain')
const stateLoading     = $el('state-loading')
const stateResult      = $el('state-result')
const stateOffline     = $el('state-offline')
const verdictBanner    = $el('verdict-banner')
const verdictIconWrap  = $el('verdict-icon-wrap')
const verdictLabel     = $el('verdict-label')
const verdictSub       = $el('verdict-sub')
const threatScoreVal   = $el('threat-score-val')
const ringFg           = $svg('ring-fg')
const metricConf       = $el('metric-conf')
const metricLatency    = $el('metric-latency')
const metricCache      = $el('metric-cache')
const reasonsList      = $el('reasons-list')
const shapLoading      = $el('shap-loading')
const noAuthStrip      = $el('no-auth-strip')
const btnViewReport    = $el('btn-view-report') as HTMLButtonElement
const btnRescan        = $el('btn-rescan') as HTMLButtonElement
const btnRetry         = $el('btn-retry') as HTMLButtonElement
const btnOpenDash      = $el('btn-open-dashboard') as HTMLButtonElement
const btnLoginNudge    = $el('btn-login-nudge') as HTMLButtonElement

// ── Constants ──────────────────────────────────────────────────────────────
const DASHBOARD_URL = 'http://localhost:3000'
const THREAT_WEIGHTS: Record<string, number> = {
  phishing:   1.0,
  malware:    0.95,
  defacement: 0.7,
  legitimate: 0.0,
}

const VERDICT_CONFIG: Record<PredictionClass, { label: string; sub: string; color: string; iconSvg: string; bannerClass: string }> = {
  legitimate: {
    label: 'Safe',
    sub: 'No threats detected',
    color: '#22c55e',
    bannerClass: 'verdict-safe',
    iconSvg: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="#22c55e" stroke-width="2.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
    </svg>`,
  },
  phishing: {
    label: 'Phishing',
    sub: 'Credential theft risk',
    color: '#ef4444',
    bannerClass: 'verdict-phishing',
    iconSvg: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="#ef4444" stroke-width="2.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
    </svg>`,
  },
  malware: {
    label: 'Malware',
    sub: 'Malicious software risk',
    color: '#f97316',
    bannerClass: 'verdict-malware',
    iconSvg: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="#f97316" stroke-width="2.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
    </svg>`,
  },
  defacement: {
    label: 'Defacement',
    sub: 'Site integrity risk',
    color: '#f59e0b',
    bannerClass: 'verdict-defacement',
    iconSvg: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="#f59e0b" stroke-width="2.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
    </svg>`,
  },
}

// ── Helpers ────────────────────────────────────────────────────────────────

function showState(state: 'loading' | 'result' | 'offline') {
  stateLoading.classList.toggle('hidden', state !== 'loading')
  stateResult.classList.toggle('hidden', state !== 'result')
  stateOffline.classList.toggle('hidden', state !== 'offline')
}

function getDomain(url: string): string {
  try { return new URL(url).hostname } catch { return url }
}

function computeThreatScore(prediction: string, confidence: number): number {
  return Math.round((THREAT_WEIGHTS[prediction] ?? 0) * confidence * 100)
}

function animateRing(score: number, color: string) {
  // SVG ring circumference for r=15.9: 2π*15.9 ≈ 99.9
  const circumference = 99.9
  const fill = (score / 100) * circumference
  ringFg.setAttribute('stroke-dasharray', `${fill} ${circumference - fill}`)
  ringFg.setAttribute('stroke', color)
}

function renderScan(url: string, scan: ScanResult) {
  const cfg = VERDICT_CONFIG[scan.prediction] ?? VERDICT_CONFIG.legitimate
  const score = computeThreatScore(scan.prediction, scan.confidence)

  // Header domain
  headerDomain.textContent = getDomain(url)

  // Banner
  verdictBanner.className = `verdict-banner ${cfg.bannerClass}`
  verdictIconWrap.innerHTML = cfg.iconSvg
  verdictIconWrap.style.background = `${cfg.color}20`
  verdictLabel.textContent = cfg.label
  verdictLabel.style.color = cfg.color
  verdictSub.textContent = cfg.sub

  // Ring
  threatScoreVal.textContent = String(score)
  animateRing(score, cfg.color)

  // Metrics
  metricConf.textContent = `${(scan.confidence * 100).toFixed(1)}%`
  metricLatency.textContent = scan.cache_hit ? `<5ms` : `${scan.latency_ms.toFixed(0)}ms`
  metricCache.textContent = scan.cache_hit ? 'HIT' : 'MISS'
  metricCache.style.color = scan.cache_hit ? '#22c55e' : '#6e7781'
}

function renderReasons(explain: ExplainResult | null) {
  shapLoading.classList.toggle('hidden', explain !== null)
  reasonsList.innerHTML = ''

  if (!explain || explain.top_reasons.length === 0) return

  const maxImpact = Math.max(...explain.top_reasons.map(r => Math.abs(r.impact)), 0.001)

  explain.top_reasons.slice(0, 5).forEach(reason => {
    const isRisk = reason.impact > 0
    const color = isRisk ? '#ef4444' : '#22c55e'
    const pct = Math.round((Math.abs(reason.impact) / maxImpact) * 100)
    const sign = isRisk ? '+' : '−'

    const li = document.createElement('li')
    li.className = 'reason-item'
    li.innerHTML = `
      <div class="reason-top">
        <span class="reason-name">${reason.feature}</span>
        <span class="reason-impact" style="color:${color}">${sign}${Math.abs(reason.impact).toFixed(3)}</span>
      </div>
      ${reason.description ? `<p class="reason-desc">${reason.description}</p>` : ''}
      <div class="reason-bar-wrap">
        <div class="reason-bar" style="width:${pct}%;background:${color}"></div>
      </div>
    `
    reasonsList.appendChild(li)
  })
}

// ── Main Render ────────────────────────────────────────────────────────────

let currentScanId: number | undefined
let currentUrl: string | undefined

async function render() {
  const stored = await chrome.storage.local.get([
    'current_url',
    'current_scan',
    'current_explain',
    'auth_token',
  ])

  const url    = stored['current_url'] as string | undefined
  const scan   = stored['current_scan'] as ScanResult | null | undefined
  const explain= stored['current_explain'] as ExplainResult | null | undefined
  const token  = stored['auth_token'] as string | undefined

  // Show no-auth strip if no token
  noAuthStrip.classList.toggle('hidden', !!token)

  if (!url) {
    showState('offline')
    return
  }

  if (!scan) {
    // No result yet — check if it's a loading or offline situation
    showState('loading')
    return
  }

  currentUrl = url
  currentScanId = scan.scan_id

  showState('result')
  renderScan(url, scan)
  renderReasons(explain ?? null)

  // Update view report button
  btnViewReport.onclick = () => {
    const path = currentScanId
      ? `/history`
      : '/dashboard'
    chrome.tabs.create({ url: `${DASHBOARD_URL}${path}` })
  }
}

// ── Storage Change Listener (live updates when SHAP arrives) ───────────────

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return
  if (changes['current_scan'] || changes['current_explain'] || changes['current_url']) {
    render()
  }
})

// ── Button Handlers ────────────────────────────────────────────────────────

btnOpenDash.onclick = () => chrome.tabs.create({ url: DASHBOARD_URL })

btnRescan.onclick = async () => {
  if (!currentUrl) return
  showState('loading')
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  chrome.runtime.sendMessage({ type: 'RESCAN', url: currentUrl, tabId: tab?.id })
}

btnRetry.onclick = async () => {
  showState('loading')
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (tab?.url && tab?.id) {
    chrome.runtime.sendMessage({ type: 'RESCAN', url: tab.url, tabId: tab.id })
  }
}

btnLoginNudge.onclick = () => chrome.tabs.create({ url: `${DASHBOARD_URL}/login` })

// ── Init ──────────────────────────────────────────────────────────────────

// If there's no stored scan for the current active tab, trigger a scan
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.url || !tab?.id) { showState('offline'); return }

  // Set domain immediately in header
  headerDomain.textContent = getDomain(tab.url)

  // Render from storage
  await render()

  // If the stored URL doesn't match the active tab, ask the SW to scan
  const stored = await chrome.storage.local.get('current_url')
  if (stored['current_url'] !== tab.url) {
    showState('loading')
    chrome.runtime.sendMessage({ type: 'RESCAN', url: tab.url, tabId: tab.id })
  }
}

init()
