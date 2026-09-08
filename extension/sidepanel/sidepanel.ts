// extension/sidepanel/sidepanel.ts

let scannedCount = 0;
let blockedCount = 0;
let totalLatency = 0;

function updateUI() {
  chrome.storage.local.get(['current_url', 'current_scan', 'current_explain'], (data) => {
    const url = data.current_url || 'No active web page';
    const scan = data.current_scan;
    const explain = data.current_explain;

    const urlElem = document.getElementById('current-url');
    if (urlElem) urlElem.textContent = url;

    const banner = document.getElementById('verdict-banner');
    const icon = document.getElementById('verdict-icon');
    const title = document.getElementById('verdict-title');
    const sub = document.getElementById('verdict-sub');
    const statusPill = document.getElementById('status-pill');

    if (!scan) {
      if (title) title.textContent = 'Analyzing website...';
      if (sub) sub.textContent = 'Running XGBoost ML models & heuristics...';
      if (icon) icon.textContent = '⏳';
      return;
    }

    scannedCount++;
    if (scan.latency_ms) totalLatency += scan.latency_ms;
    const avgLatency = Math.round(totalLatency / Math.max(1, scannedCount));

    const statScanned = document.getElementById('stat-scanned');
    const statBlocked = document.getElementById('stat-blocked');
    const statLatency = document.getElementById('stat-latency');

    if (statScanned) statScanned.textContent = String(scannedCount);
    if (statLatency) statLatency.textContent = `${avgLatency}ms`;

    const isThreat = scan.prediction !== 'legitimate';
    if (isThreat) {
      blockedCount++;
      if (statBlocked) statBlocked.textContent = String(blockedCount);
    }

    if (statusPill) {
      statusPill.textContent = isThreat ? 'Threat Alert' : 'Protected';
      statusPill.className = `pill ${isThreat ? 'pill-danger' : 'pill-safe'}`;
    }

    if (banner) {
      banner.className = `verdict-banner ${isThreat ? 'banner-phishing' : 'banner-legitimate'}`;
    }
    if (icon) icon.textContent = isThreat ? '🚨' : '✅';
    if (title) title.textContent = isThreat ? `${scan.prediction.toUpperCase()} DETECTED` : 'Legitimate Website';
    if (sub) {
      sub.textContent = `Confidence: ${(scan.confidence * 100).toFixed(1)}% · Latency: ${scan.latency_ms || 12}ms`;
    }

    // Render SHAP reasons
    const reasonsContainer = document.getElementById('reasons-list');
    if (reasonsContainer) {
      reasonsContainer.innerHTML = '';
      if (explain && explain.top_reasons && explain.top_reasons.length > 0) {
        explain.top_reasons.forEach((r: any) => {
          const div = document.createElement('div');
          div.className = 'reason-item';
          div.innerHTML = `<span><strong>${r.feature}</strong> = ${r.value}</span><span style="color: #EF4444;">+${(r.impact * 100).toFixed(1)}%</span>`;
          reasonsContainer.appendChild(div);
        });
      } else {
        reasonsContainer.innerHTML = '<div class="empty-state">No elevated threat factors detected for this domain.</div>';
      }
    }
  });
}

// Update on initial load and listen for storage changes
updateUI();
chrome.storage.onChanged.addListener((changes) => {
  if (changes.current_scan || changes.current_url || changes.current_explain) {
    updateUI();
  }
});
