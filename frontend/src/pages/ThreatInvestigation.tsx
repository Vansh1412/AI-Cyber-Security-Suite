import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Globe, AlertTriangle, ShieldCheck, ChevronRight,
  Layers, Loader2, Clock, Activity, Server, Info, Link2
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { clsx } from 'clsx'
import { scanService } from '@/services/scan'
import type { BulkScanResponse, DomainScanHistory, BulkScanItem, PredictionClass } from '@/types'

const PRED_COLOR: Record<string, string> = {
  legitimate: 'text-safe-500',
  phishing:   'text-threat-500',
  malware:    'text-orange-400',
  defacement: 'text-suspicious-500',
}

const PRED_BG: Record<string, string> = {
  legitimate: 'bg-safe-500/10 border-safe-500/30',
  phishing:   'bg-threat-500/10 border-threat-500/30',
  malware:    'bg-orange-500/10 border-orange-500/30',
  defacement: 'bg-suspicious-500/10 border-suspicious-500/30',
}

// ── Bulk Scan Section ────────────────────────────────────────────────────────

function BulkScanPanel() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<BulkScanResponse | null>(null)

  const handleBulkScan = async () => {
    const urls = input
      .split('\n')
      .map(u => u.trim())
      .filter(Boolean)

    if (!urls.length) { toast.error('Enter at least one URL.'); return }
    if (urls.length > 20) { toast.error('Maximum 20 URLs per batch.'); return }

    setLoading(true)
    setResult(null)
    try {
      const data = await scanService.bulkScan(urls)
      setResult(data)
    } catch (err: any) {
      const msg = err?.response?.data?.detail || 'Bulk scan failed.'
      toast.error(typeof msg === 'string' ? msg : 'Bulk scan failed.')
    } finally {
      setLoading(false)
    }
  }

  const threats = result?.results.filter(r => r.prediction && r.prediction !== 'legitimate') ?? []
  const errors  = result?.results.filter(r => !!r.error) ?? []

  return (
    <div className="glass-card p-6 space-y-4">
      <div className="flex items-center gap-2 mb-1">
        <Layers size={16} className="text-primary-400" />
        <h3 className="font-semibold text-white">Bulk URL Scanner</h3>
        <span className="text-xs text-gray-500 ml-auto">Max 20 URLs</span>
      </div>

      <textarea
        value={input}
        onChange={e => setInput(e.target.value)}
        placeholder={"https://example.com\nhttps://suspicious.xyz\nhttps://test.phish.com"}
        rows={6}
        className="w-full bg-dark-bg border border-dark-border rounded-xl p-3 text-sm font-mono
                   text-gray-300 placeholder:text-gray-600 focus:outline-none focus:border-primary-500
                   resize-none transition-colors"
        spellCheck={false}
      />

      <div className="flex gap-3 items-center">
        <button
          onClick={handleBulkScan}
          disabled={loading || !input.trim()}
          className="btn-primary"
        >
          {loading ? <Loader2 size={15} className="animate-spin" /> : <Layers size={15} />}
          {loading ? 'Scanning...' : 'Scan Batch'}
        </button>
        {result && (
          <span className="text-xs text-gray-500">
            {result.total} URLs · {result.elapsed_ms.toFixed(0)}ms · {threats.length} threat{threats.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Results grid */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="space-y-2 overflow-hidden"
          >
            <div className="border-t border-dark-border pt-4">
              <p className="text-xs text-gray-500 mb-3 font-medium uppercase tracking-wide">
                Results ({result.total} URLs)
              </p>
              <div className="space-y-2">
                {result.results.map((item, i) => (
                  <BulkResultRow key={i} item={item} />
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function BulkResultRow({ item }: { item: BulkScanItem }) {
  if (item.error) {
    return (
      <div className="flex items-center gap-3 p-3 rounded-lg bg-dark-bg/50 border border-dark-border">
        <AlertTriangle size={13} className="text-gray-500 shrink-0" />
        <span className="text-xs font-mono text-gray-400 flex-1 truncate">{item.url}</span>
        <span className="text-xs text-gray-500">Error: {item.error}</span>
      </div>
    )
  }

  const pred = item.prediction ?? 'unknown'
  const colorClass = PRED_COLOR[pred] ?? 'text-gray-400'
  const isSafe = pred === 'legitimate'

  return (
    <div className={clsx('flex items-center gap-3 p-3 rounded-lg border', PRED_BG[pred] ?? 'bg-dark-bg/50 border-dark-border')}>
      {isSafe
        ? <ShieldCheck size={13} className="text-safe-500 shrink-0" />
        : <AlertTriangle size={13} className="text-threat-500 shrink-0" />
      }
      <span className="text-xs font-mono text-gray-300 flex-1 truncate">{item.url}</span>
      <span className={clsx('text-xs font-bold uppercase', colorClass)}>{pred}</span>
      <span className="text-xs text-gray-500">{((item.confidence ?? 0) * 100).toFixed(1)}%</span>
      {item.latency_ms && (
        <span className="text-xs text-gray-600">{item.latency_ms.toFixed(0)}ms</span>
      )}
    </div>
  )
}

// ── Domain History Section ────────────────────────────────────────────────────

function DomainHistoryPanel() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<DomainScanHistory | null>(null)

  const handleSearch = async () => {
    const d = domain.trim().toLowerCase()
    if (!d) { toast.error('Enter a domain name.'); return }

    setLoading(true)
    setResult(null)
    try {
      const data = await scanService.getDomainHistory(d)
      setResult(data)
    } catch (err: any) {
      if (err?.response?.status === 404) {
        toast.error(`No scan history found for: ${d}`)
      } else {
        const msg = err?.response?.data?.detail || 'Search failed.'
        toast.error(typeof msg === 'string' ? msg : 'Search failed.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="glass-card p-6 space-y-4">
      <div className="flex items-center gap-2 mb-1">
        <Globe size={16} className="text-accent-400" />
        <h3 className="font-semibold text-white">Domain Investigation</h3>
      </div>

      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !loading && handleSearch()}
            placeholder="example.com or suspicious-domain.xyz"
            className="input-field pl-9 text-sm font-mono"
          />
        </div>
        <button
          onClick={handleSearch}
          disabled={loading || !domain.trim()}
          className="btn-primary shrink-0"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
          Search
        </button>
      </div>

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="border-t border-dark-border pt-4 space-y-4"
          >
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: 'Domain',          value: result.domain, icon: Globe },
                { label: 'Total Scans',     value: result.total_scans.toString(), icon: Activity },
                { label: 'Threats Found',   value: result.threat_count.toString(), icon: AlertTriangle },
                { label: 'Latest',          value: result.latest_prediction ?? '—', icon: Clock },
              ].map(stat => (
                <div key={stat.label} className="p-3 rounded-xl bg-dark-bg/50 border border-dark-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <stat.icon size={11} className="text-gray-500" />
                    <p className="text-xs text-gray-500">{stat.label}</p>
                  </div>
                  <p className={clsx(
                    'text-sm font-bold truncate',
                    stat.label === 'Latest' ? (PRED_COLOR[result.latest_prediction ?? ''] ?? 'text-white') : 'text-white'
                  )}>
                    {stat.value}
                  </p>
                </div>
              ))}
            </div>

            {/* Scan list */}
            <div>
              <p className="text-xs text-gray-500 font-medium uppercase tracking-wide mb-2">
                Scan History (newest first)
              </p>
              <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                {result.scans.map(scan => (
                  <div
                    key={scan.id}
                    className="flex items-center gap-3 p-2.5 rounded-lg bg-dark-bg/50 border border-dark-border hover:border-dark-border/80 transition-colors"
                  >
                    <span className={clsx('text-xs font-bold w-20 shrink-0', PRED_COLOR[scan.prediction] ?? 'text-gray-400')}>
                      {scan.prediction}
                    </span>
                    <Link2 size={11} className="text-gray-600 shrink-0" />
                    <span className="text-xs font-mono text-gray-400 flex-1 truncate">{scan.url}</span>
                    <span className="text-xs text-gray-600 shrink-0">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </span>
                    <span className="text-xs font-semibold text-gray-300 shrink-0 w-12 text-right">
                      {((scan.confidence ?? 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ── Intel Info Panel ─────────────────────────────────────────────────────────

function IntelInfoCard() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="glass-card p-5"
    >
      <div className="flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary-500/10">
          <Info size={15} className="text-primary-400" />
        </div>
        <div className="space-y-1">
          <p className="text-sm font-semibold text-white">About Threat Investigation</p>
          <p className="text-xs text-gray-400 leading-relaxed">
            Use the <strong className="text-gray-300">Bulk Scanner</strong> to scan up to 50 URLs at once through the ML pipeline.
            Use <strong className="text-gray-300">Domain Investigation</strong> to look up your full scan history for any domain,
            identify repeat threats, and correlate attack campaigns. Results are scoped to your account.
          </p>
          <div className="flex gap-4 pt-2 flex-wrap">
            {[
              { icon: Server, text: 'ML-powered classification' },
              { icon: ChevronRight, text: 'Max 50 URLs per batch' },
              { icon: ShieldCheck, text: 'No external API calls for bulk' },
            ].map(item => (
              <div key={item.text} className="flex items-center gap-1.5 text-xs text-gray-500">
                <item.icon size={11} className="text-primary-400" />
                {item.text}
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ThreatInvestigation() {
  return (
    <div className="max-w-4xl mx-auto space-y-5">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-white">Threat Investigation</h2>
        <p className="text-gray-400 text-sm mt-0.5">
          Bulk scan URLs and investigate domain history for threat correlation.
        </p>
      </div>

      <IntelInfoCard />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <BulkScanPanel />
        <DomainHistoryPanel />
      </div>
    </div>
  )
}
