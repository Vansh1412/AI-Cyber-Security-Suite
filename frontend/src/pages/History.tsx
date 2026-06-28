import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Search, Loader2, Shield, AlertTriangle, X, Trash2,
  ExternalLink, RefreshCw, Download, ChevronLeft, ChevronRight
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import { clsx } from 'clsx'
import { scanService } from '@/services/scan'
import { ShapExplanation } from '@/components/scan/ShapExplanation'
import { ThreatGauge } from '@/components/scan/ThreatGauge'
import { ReportExporter } from '@/components/scan/ReportExporter'
import type { HistoryItem, PredictionClass } from '@/types'

type FilterType = 'all' | PredictionClass

const BADGE: Record<PredictionClass, string> = {
  legitimate: 'badge-safe',
  phishing:   'badge-phishing',
  malware:    'badge-malware',
  defacement: 'badge-defacement',
}

function threatScore(p: string, c: number) {
  const w: Record<string, number> = { phishing: 1.0, malware: 0.95, defacement: 0.7, legitimate: 0.0 }
  return Math.round((w[p] ?? 0) * c * 100)
}

// ── Detail Modal ─────────────────────────────────────────────────────────────
function ReportModal({ item, onClose }: { item: HistoryItem; onClose: () => void }) {
  const score = threatScore(item.prediction, item.confidence)

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95 }}
          onClick={e => e.stopPropagation()}
          className="glass-card w-full max-w-2xl max-h-[85vh] overflow-y-auto"
        >
          {/* Header */}
          <div className="flex items-center justify-between p-5 border-b border-dark-border sticky top-0 bg-dark-card z-10">
            <div>
              <h3 className="font-bold text-white">Scan Report</h3>
              <p className="text-xs text-gray-500 font-mono truncate max-w-sm">{item.url}</p>
            </div>
            <button onClick={onClose} className="btn-ghost p-2"><X size={18} /></button>
          </div>

          <div className="p-6 space-y-6">
            {/* Gauge + info */}
            <div className="flex items-center gap-6">
              <ThreatGauge score={score} size={120} />
              <div className="flex-1 space-y-2">
                <div className="flex gap-2 items-center">
                  <span className={BADGE[item.prediction]}>
                    {item.prediction === 'legitimate'
                      ? <><Shield size={10} /> Safe</>
                      : <><AlertTriangle size={10} /> {item.prediction}</>
                    }
                  </span>
                  <span className="text-sm text-white font-semibold">{(item.confidence * 100).toFixed(2)}%</span>
                </div>
                <p className="text-xs text-gray-500">{new Date(item.created_at).toLocaleString()}</p>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    ['Latency', `${item.latency_ms?.toFixed(1) ?? '—'}ms`],
                    ['Cache', item.cache_hit ? 'HIT' : 'MISS'],
                  ].map(([l, v]) => (
                    <div key={l} className="p-2 rounded-lg bg-dark-bg/50 border border-dark-border">
                      <p className="text-xs text-gray-500">{l}</p>
                      <p className="text-xs text-white font-mono">{v}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* SHAP */}
            {item.top_reasons && item.top_reasons.length > 0 && (
              <div className="border-t border-dark-border pt-5">
                <ShapExplanation reasons={item.top_reasons} prediction={item.prediction} />
              </div>
            )}

            {/* Export */}
            <div className="border-t border-dark-border pt-4">
              <ReportExporter
                url={item.url}
                prediction={item.prediction}
                confidence={item.confidence}
                threatScore={score}
                latencyMs={item.latency_ms}
                reasons={item.top_reasons ?? undefined}
              />
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

// ── History Page ─────────────────────────────────────────────────────────────
export default function History() {
  const [page, setPage]         = useState(1)
  const [search, setSearch]     = useState('')
  const [filter, setFilter]     = useState<FilterType>('all')
  const [selected, setSelected] = useState<HistoryItem | null>(null)
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['history', page],
    queryFn: () => scanService.getHistory(page, 20),
    retry: 1,
  })

  const handleDelete = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await scanService.deleteHistoryItem(id)
      toast.success('Record deleted.')
      queryClient.invalidateQueries({ queryKey: ['history'] })
    } catch {
      toast.error('Delete failed.')
    }
  }

  const handleExportCsv = () => {
    if (!data) return
    const rows = [
      ['ID','URL','Prediction','Confidence','Latency(ms)','Cached','Time'],
      ...data.map(d => [
        d.id, d.url, d.prediction,
        (d.confidence * 100).toFixed(2)+'%',
        d.latency_ms?.toFixed(1) ?? '',
        d.cache_hit ? 'Yes' : 'No',
        new Date(d.created_at).toISOString()
      ])
    ]
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `scan-history-${Date.now()}.csv`; a.click()
    toast.success('CSV exported!')
  }

  const filtered = (data ?? []).filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(search.toLowerCase())
    const matchesFilter = filter === 'all' || item.prediction === filter
    return matchesSearch && matchesFilter
  })

  const filters: { key: FilterType; label: string }[] = [
    { key: 'all',         label: 'All' },
    { key: 'legitimate',  label: 'Safe' },
    { key: 'phishing',    label: 'Phishing' },
    { key: 'malware',     label: 'Malware' },
    { key: 'defacement',  label: 'Defacement' },
  ]

  return (
    <>
      {selected && <ReportModal item={selected} onClose={() => setSelected(null)} />}

      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h2 className="text-2xl font-bold text-white">Scan History</h2>
            <p className="text-gray-400 text-sm mt-0.5">All URLs you've analyzed — click any row to view the full report.</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => refetch()} className="btn-ghost text-sm">
              <RefreshCw size={14} /> Refresh
            </button>
            <button onClick={handleExportCsv} disabled={!data?.length} className="btn-secondary text-sm py-2 px-3">
              <Download size={14} /> Export CSV
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="glass-card p-4 flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              placeholder="Search URLs..."
              className="input-field pl-9 py-2 text-sm"
            />
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {filters.map(f => (
              <button
                key={f.key}
                onClick={() => { setFilter(f.key); setPage(1) }}
                className={clsx('px-3 py-1.5 rounded-lg text-xs font-medium transition-colors', {
                  'bg-primary-600 text-white':          filter === f.key,
                  'bg-dark-card text-gray-400 hover:text-white hover:bg-dark-hover': filter !== f.key,
                })}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Table */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="glass-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border bg-dark-bg/30">
                {['URL', 'Prediction', 'Confidence', 'Latency', 'Cached', 'Time', ''].map(h => (
                  <th key={h} className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wider px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center">
                  <Loader2 size={24} className="animate-spin text-gray-500 mx-auto" />
                </td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-500 text-sm">
                  {search || filter !== 'all' ? 'No results match your filters.' : 'No scans yet. Scan your first URL!'}
                </td></tr>
              ) : filtered.map(item => (
                <tr
                  key={item.id}
                  onClick={() => setSelected(item)}
                  className="border-b border-dark-border last:border-0 hover:bg-dark-hover cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3.5">
                    <p className="font-mono text-sm text-white truncate max-w-[220px]">{item.url}</p>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className={BADGE[item.prediction]}>
                      {item.prediction === 'legitimate'
                        ? <><Shield size={10} /> Safe</>
                        : <><AlertTriangle size={10} /> {item.prediction}</>
                      }
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-sm text-white">{(item.confidence * 100).toFixed(1)}%</td>
                  <td className="px-4 py-3.5 text-sm text-gray-400 font-mono">{item.latency_ms?.toFixed(1) ?? '—'}ms</td>
                  <td className="px-4 py-3.5">
                    <span className={clsx('text-xs font-medium', item.cache_hit ? 'text-safe-500' : 'text-gray-500')}>
                      {item.cache_hit ? '✓' : '✗'}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-xs text-gray-400">{new Date(item.created_at).toLocaleString()}</td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={e => { e.stopPropagation(); setSelected(item) }}
                        className="p-1.5 rounded-lg text-gray-500 hover:text-primary-400 hover:bg-primary-500/10 transition-colors"
                        title="View Report"
                      >
                        <ExternalLink size={14} />
                      </button>
                      <button
                        onClick={e => handleDelete(item.id, e)}
                        className="p-1.5 rounded-lg text-gray-500 hover:text-threat-500 hover:bg-threat-500/10 transition-colors"
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        {/* Pagination */}
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">{filtered.length} result{filtered.length !== 1 ? 's' : ''}</p>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage(p => Math.max(1, p-1))} disabled={page === 1} className="btn-ghost p-2 disabled:opacity-40">
              <ChevronLeft size={16} />
            </button>
            <span className="text-sm text-gray-400 px-2">Page {page}</span>
            <button onClick={() => setPage(p => p+1)} disabled={(data?.length ?? 0) < 20} className="btn-ghost p-2 disabled:opacity-40">
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
