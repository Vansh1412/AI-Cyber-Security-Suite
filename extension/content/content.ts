// content/content.ts
// ─────────────────────────────────────────────────────────────────────────────
// Content script — injected into every HTTP/HTTPS page.
// Responsibilities:
//   1. Reports page URL to service worker on load (redundant safety net)
//   2. Bridges context menu "Analyze This Link" clicks
// ─────────────────────────────────────────────────────────────────────────────

// Listen for messages from the popup or service worker
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'PING') {
    // Used by popup to check if content script is alive
    return true
  }
})

// Export empty to satisfy TS module mode
export {}
