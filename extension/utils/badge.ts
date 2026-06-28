// utils/badge.ts — Badge color and text helpers

export type BadgeMode = 'loading' | 'safe' | 'phishing' | 'malware' | 'defacement' | 'offline' | 'error'

interface BadgeConfig {
  color: string
  text: string
  title: string
}

const BADGE_CONFIGS: Record<BadgeMode, BadgeConfig> = {
  loading:    { color: '#6e7781', text: '...',  title: 'Scanning...' },
  safe:       { color: '#22c55e', text: 'SAFE', title: 'This site appears safe' },
  phishing:   { color: '#ef4444', text: 'RISK', title: '⚠️ Phishing detected!' },
  malware:    { color: '#f97316', text: 'RISK', title: '⚠️ Malware detected!' },
  defacement: { color: '#f59e0b', text: 'WARN', title: '⚠️ Defacement detected!' },
  offline:    { color: '#94a3b8', text: '?',    title: 'AI service offline' },
  error:      { color: '#94a3b8', text: '!',    title: 'Scan error — click for details' },
}

/**
 * Convert a prediction class string to a BadgeMode.
 */
export function predictionToMode(prediction: string): BadgeMode {
  switch (prediction) {
    case 'legitimate': return 'safe'
    case 'phishing':   return 'phishing'
    case 'malware':    return 'malware'
    case 'defacement': return 'defacement'
    default:           return 'error'
  }
}

/**
 * Apply badge color and text to a specific tab.
 */
export async function setBadge(tabId: number, mode: BadgeMode): Promise<void> {
  const config = BADGE_CONFIGS[mode]
  try {
    await chrome.action.setBadgeBackgroundColor({ color: config.color, tabId })
    await chrome.action.setBadgeText({ text: config.text, tabId })
    await chrome.action.setTitle({ title: config.title, tabId })
  } catch {
    // Tab may have been closed — ignore
  }
}

/**
 * Apply badge to ALL tabs (e.g., offline state).
 */
export async function setBadgeGlobal(mode: BadgeMode): Promise<void> {
  const config = BADGE_CONFIGS[mode]
  try {
    await chrome.action.setBadgeBackgroundColor({ color: config.color })
    await chrome.action.setBadgeText({ text: config.text })
    await chrome.action.setTitle({ title: config.title })
  } catch {
    // Ignore
  }
}

/**
 * Clear badge for a tab (e.g., chrome:// pages).
 */
export async function clearBadge(tabId: number): Promise<void> {
  try {
    await chrome.action.setBadgeText({ text: '', tabId })
    await chrome.action.setTitle({ title: 'AI Cyber Security Suite', tabId })
  } catch {
    // Ignore
  }
}

/**
 * Compute a 0-100 threat score from prediction + confidence.
 */
export function computeThreatScore(prediction: string, confidence: number): number {
  const weights: Record<string, number> = {
    phishing:   1.0,
    malware:    0.95,
    defacement: 0.7,
    legitimate: 0.0,
  }
  return Math.round((weights[prediction] ?? 0) * confidence * 100)
}
