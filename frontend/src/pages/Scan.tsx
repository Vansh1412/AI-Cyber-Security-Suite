import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Loader2, ShieldCheck, AlertTriangle, Zap, Clock, Wifi,
  ChevronDown, ChevronUp, Shield
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { clsx } from 'clsx'
import { scanService } from '@/services/scan'
import type { ScanResult, ExplainResult, PredictionClass } from '@/types'
import { ThreatGauge } from '@/components/scan/ThreatGauge'
import { ThreatTimeline } from '@/components/scan/ThreatTimeline'
import { ShapExplanation } from '@/components/scan/ShapExplanation'
import { ReportExporter } from '@/components/scan/ReportExporter'

// ── Config ──────────────────────────────────────────────────────────────────
const PRED_CFG: Record<PredictionClass, {
  label: string; color: string; bg: string; border: string; icon: typeof ShieldCheck
}> = {
  legitimate:  { label: 'Safe',        color: 'text-safe-500',       bg: 'bg-safe-500/10',       border: 'border-safe-500/30',       icon: ShieldCheck   },
  phishing:    { label: 'Phishing',    color: 'text-threat-500',     bg: 'bg-threat-500/10',     border: 'border-threat-500/30',     icon: AlertTriangle },
  malware:     { label: 'Malware',     color: 'text-orange-400',     bg: 'bg-orange-500/10',     border: 'border-orange-500/30',     icon: AlertTriangle },
  defacement:  { label: 'Defacement',  color: 'text-suspicious-500', bg: 'bg-suspicious-500/10', border: 'border-suspicious-500/30', icon: AlertTriangle },
}

function threatScore(prediction: string, confidence: number): number {
  const w: Record<string, number> = { phishing: 1.0, malware: 0.95, defacement: 0.7, legitimate: 0.0 }
  return Math.round((w[prediction] ?? 0) * confidence * 100)
}

// ── Scan Page ────────────────────────────────────────────────────────────────
export default function Scan() {
  const [url, setUrl]             = useState('')
  const [scanning, setScanning]   = useState(false)
  const [explaining, setExplaining] = useState(false)
  const [scan, setScan]           = useState<ScanResult | null>(null)
  const [explain, setExplain]     = useState<ExplainResult | null>(null)
  const [detailsOpen, setDetailsOpen] = useState(false)

  const handleScan = async () => {
    const trimmed = url.trim()
    if (!trimmed) { toast.error('Please enter a URL.'); return }
    setScanning(true); setScan(null); setExplain(null)
    try {
      const data = await scanService.scanUrl(trimmed)
      setScan(data)
      // Fire explain concurrently in background
      setExplaining(true)
      scanService.explainUrl(trimmed)
        .then(e => setExplain(e))
        .catch(() => {}) // graceful — SHAP may time out
        .finally(() => setExplaining(false))
    } catch (err: any) {
      const detail = err?.response?.data?.detail
      const errMsg = Array.isArray(detail) ? detail[0]?.msg : detail
      toast.error(typeof errMsg === 'string' ? errMsg : 'Scan failed. Is the API running?')
    } finally {
      setScanning(false)
    }
  }

  const cfg = scan ? PRED_CFG[scan.prediction as PredictionClass] : null
  const score = scan ? threatScore(scan.prediction, scan.confidence) : 0

  return (
    <div className="max-w-3xl mx-auto space-y-5">

      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-white">URL Scanner</h2>
        <p className="text-gray-400 text-sm mt-0.5">AI-powered threat detection with SHAP explanations.</p>
      </div>

      {/* Input Card */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
              type="url"
              placeholder="https://suspicious-domain.xyz/login"
              className="input-field pl-11 font-mono text-sm"
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="btn-primary shrink-0 min-w-28 justify-center"
          >
            {scanning ? <Loader2 size={16} className="animate-spin" /> : <Zap size={16} />}
            {scanning ? 'Scanning...' : 'Analyze'}
          </button>
        </div>

        {/* Progress bar */}
        {scanning && (
          <div className="mt-4 relative h-1 rounded-full bg-dark-muted overflow-hidden">
            <motion.div
              className="absolute inset-y-0 left-0 w-2/5 bg-gradient-to-r from-primary-600 to-accent-500 rounded-full"
              animate={{ x: ['0%', '175%'] }}
              transition={{ duration: 1.0, repeat: Infinity, ease: 'easeInOut' }}
            />
          </div>
        )}
      </motion.div>

      {/* Result */}
      <AnimatePresence mode="wait">
        {scan && cfg && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={clsx('glass-card overflow-hidden border', cfg.border)}
          >
            {/* Verdict header bar */}
            <div className={clsx('px-6 py-4', cfg.bg)}>
              <div className="flex items-center gap-2">
                <cfg.icon size={18} className={cfg.color} />
                <span className={clsx('font-bold tracking-wide uppercase', cfg.color)}>{cfg.label}</span>
                <span className="text-gray-500 text-sm ml-2 truncate font-mono">{scan.url}</span>
              </div>
            </div>

            {/* Main body — Gauge + quick stats */}
            <div className="p-6">
              <div className="flex flex-col md:flex-row gap-6 items-start md:items-center">

                {/* Gauge */}
                <div className="shrink-0">
                  <ThreatGauge score={score} />
                </div>

                {/* Quick stats */}
                <div className="flex-1 grid grid-cols-2 sm:grid-cols-3 gap-4">
                  <div className="text-center p-4 rounded-xl bg-dark-bg/50 border border-dark-border">
                    <p className={clsx('text-2xl font-black', cfg.color)}>
                      {(scan.confidence * 100).toFixed(1)}%
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">Confidence</p>
                  </div>
                  <div className="text-center p-4 rounded-xl bg-dark-bg/50 border border-dark-border">
                    <div className="flex items-center justify-center gap-1 mb-0.5">
                      <Clock size={13} className="text-gray-500" />
                      <p className="text-2xl font-black text-white">{scan.latency_ms.toFixed(0)}</p>
                      <span className="text-xs text-gray-500 self-end mb-0.5">ms</span>
                    </div>
                    <p className="text-xs text-gray-500">Latency</p>
                  </div>
                  <div className="text-center p-4 rounded-xl bg-dark-bg/50 border border-dark-border col-span-2 sm:col-span-1">
                    <div className="flex items-center justify-center gap-1">
                      <Wifi size={13} className={scan.cache_hit ? 'text-safe-500' : 'text-gray-500'} />
                      <p className="text-lg font-bold text-white">{scan.cache_hit ? 'Cached' : 'Live'}</p>
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5">Source</p>
                  </div>
                </div>
              </div>

              {/* Confidence progress bar */}
              <div className="mt-6">
                <div className="flex justify-between text-xs text-gray-500 mb-1.5">
                  <span>Model confidence</span>
                  <span>{(scan.confidence * 100).toFixed(3)}%</span>
                </div>
                <div className="h-2 bg-dark-muted rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${scan.confidence * 100}%` }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                    className={clsx('h-full rounded-full', {
                      'bg-safe-500':        scan.prediction === 'legitimate',
                      'bg-threat-500':      scan.prediction === 'phishing',
                      'bg-orange-500':      scan.prediction === 'malware',
                      'bg-suspicious-500':  scan.prediction === 'defacement',
                    })}
                  />
                </div>
              </div>

              {/* Divider */}
              <div className="my-6 border-t border-dark-border" />

              {/* Two-column: Timeline + SHAP */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <ThreatTimeline prediction={scan.prediction} />

                <div>
                  {explaining && (
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Loader2 size={14} className="animate-spin" />
                      Computing SHAP explanations...
                    </div>
                  )}
                  {explain && !explaining && (
                    <ShapExplanation reasons={explain.top_reasons} prediction={explain.prediction} />
                  )}
                  {!explain && !explaining && (
                    <div className="text-sm text-gray-500">
                      <Shield size={14} className="inline mr-1.5 text-gray-600" />
                      SHAP explanation will appear here after analysis.
                    </div>
                  )}
                </div>
              </div>

              {/* Divider */}
              <div className="my-6 border-t border-dark-border" />

              {/* Export */}
              <div className="flex items-center justify-between flex-wrap gap-4">
                <ReportExporter
                  url={scan.url}
                  prediction={scan.prediction}
                  confidence={scan.confidence}
                  threatScore={score}
                  latencyMs={scan.latency_ms}
                  reasons={explain?.top_reasons}
                />

                {/* Technical details toggle */}
                <button
                  onClick={() => setDetailsOpen(!detailsOpen)}
                  className="btn-ghost text-xs"
                >
                  Technical Details {detailsOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                </button>
              </div>

              {/* Technical details collapsible */}
              <AnimatePresence>
                {detailsOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 gap-3">
                      {[
                        { label: 'Model',         value: 'XGBoost v1.4 (Calibrated)' },
                        { label: 'Schema',         value: 'v1.0 — 63 features' },
                        { label: 'API Version',    value: 'v2' },
                        { label: 'Latency',        value: `${scan.latency_ms.toFixed(2)}ms` },
                        { label: 'Cache',          value: scan.cache_hit ? 'HIT' : 'MISS' },
                        { label: 'Threat Score',   value: `${score}/100` },
                      ].map(d => (
                        <div key={d.label} className="p-3 rounded-lg bg-dark-bg/50 border border-dark-border">
                          <p className="text-xs text-gray-500 mb-0.5">{d.label}</p>
                          <p className="text-xs text-white font-mono">{d.value}</p>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
