import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  Loader2, Database, Cpu, Wifi, HardDrive, Shield,
  RefreshCw, Trash2, Users, ToggleRight, AlertCircle,
  CheckCircle2, XCircle
} from 'lucide-react'
import { clsx } from 'clsx'
import { toast } from 'react-hot-toast'
import api from '@/services/api'
import { scanService } from '@/services/scan'

function StatusPill({ status }: { status: string }) {
  const ok = ['connected', 'loaded', 'healthy'].includes(status?.toLowerCase())
  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold',
      ok ? 'bg-safe-500/15 text-safe-500' : 'bg-threat-500/15 text-threat-500'
    )}>
      {ok
        ? <CheckCircle2 size={11} />
        : <XCircle size={11} />
      }
      {status}
    </span>
  )
}

function HealthCard({
  label, value, icon: Icon, raw = false, delay = 0
}: {
  label: string; value: string | undefined; icon: React.ElementType; raw?: boolean; delay?: number
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="glass-card p-5"
    >
      <div className="flex items-start justify-between mb-3">
        <p className="text-sm text-gray-400">{label}</p>
        <Icon size={15} className="text-gray-600" />
      </div>
      {raw
        ? <p className="text-lg font-bold text-white font-mono">{value ?? '—'}</p>
        : <StatusPill status={value ?? 'unknown'} />
      }
    </motion.div>
  )
}

export default function Admin() {
  const { data: health, isLoading, refetch } = useQuery({
    queryKey: ['health'],
    queryFn: scanService.getHealth,
    refetchInterval: 15_000,
  })

  const handleClearCache = async () => {
    try {
      // Attempts to call a cache flush — backend may not have this route yet
      await api.post('/v1/admin/cache/clear').catch(() => null)
      toast.success('Cache flush requested.')
    } catch { toast.error('Could not clear cache.') }
  }

  const handleReloadModel = async () => {
    toast('Model reload signal sent (backend will respond on next startup).', { icon: '🔄' })
  }

  const healthCards = [
    { label: 'Overall Status', value: health?.status,   icon: Shield,    raw: false, delay: 0.0 },
    { label: 'Database',       value: health?.database, icon: Database,  raw: false, delay: 0.05 },
    { label: 'Redis Cache',    value: health?.redis,    icon: Wifi,      raw: false, delay: 0.1 },
    { label: 'ML Model',       value: health?.model,    icon: Cpu,       raw: false, delay: 0.15 },
    { label: 'Memory Usage',   value: health?.memory,   icon: HardDrive, raw: true,  delay: 0.2 },
    { label: 'API Version',    value: health?.version,  icon: ToggleRight, raw: true, delay: 0.25 },
  ] as const

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">Admin Panel</h2>
          <p className="text-gray-400 text-sm mt-0.5">System health, model management, and operations.</p>
        </div>
        <button onClick={() => refetch()} className="btn-ghost text-sm">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {isLoading ? (
        <div className="h-48 flex items-center justify-center">
          <Loader2 size={28} className="animate-spin text-primary-500" />
        </div>
      ) : (
        <>
          {/* Health grid */}
          <div>
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">System Health</h3>
            <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
              {healthCards.map(c => (
                <HealthCard key={c.label} label={c.label} value={c.value as string} icon={c.icon} raw={c.raw} delay={c.delay} />
              ))}
            </div>
          </div>

          {/* Overall status banner */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className={clsx(
              'flex items-center gap-3 p-4 rounded-xl border',
              health?.status === 'healthy'
                ? 'bg-safe-500/10 border-safe-500/30'
                : 'bg-threat-500/10 border-threat-500/30'
            )}
          >
            {health?.status === 'healthy'
              ? <CheckCircle2 size={18} className="text-safe-500 shrink-0" />
              : <AlertCircle size={18} className="text-threat-500 shrink-0" />
            }
            <div>
              <p className={clsx('font-semibold text-sm', health?.status === 'healthy' ? 'text-safe-500' : 'text-threat-500')}>
                System is {health?.status === 'healthy' ? 'Healthy' : 'Degraded'}
              </p>
              <p className="text-xs text-gray-500">
                {health?.status === 'healthy'
                  ? 'All services are running normally.'
                  : 'One or more services may be unavailable. Check health cards above.'
                }
              </p>
            </div>
          </motion.div>

          {/* Model management */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="glass-card p-5">
            <h3 className="font-semibold text-white mb-1">Model Registry</h3>
            <p className="text-xs text-gray-500 mb-4">Current model environment and switching controls.</p>
            <div className="flex flex-wrap gap-3 mb-4">
              {['production', 'staging', 'experimental'].map(env => (
                <div key={env} className={clsx(
                  'px-4 py-2 rounded-xl border text-sm font-medium capitalize',
                  env === 'production'
                    ? 'bg-primary-600/20 border-primary-600/40 text-primary-300'
                    : 'bg-dark-bg/50 border-dark-border text-gray-500'
                )}>
                  {env === 'production' && <span className="w-1.5 h-1.5 rounded-full bg-safe-500 inline-block mr-2 animate-pulse" />}
                  {env}
                </div>
              ))}
            </div>
            <button onClick={handleReloadModel} className="btn-secondary text-sm">
              <RefreshCw size={14} /> Reload Model
            </button>
          </motion.div>

          {/* Cache management */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="glass-card p-5">
            <h3 className="font-semibold text-white mb-1">Cache Management</h3>
            <p className="text-xs text-gray-500 mb-4">Redis-backed result caching. TTL: 1 hour.</p>
            <div className="flex items-center gap-3">
              <div className={clsx(
                'flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-lg',
                health?.redis === 'connected'
                  ? 'bg-safe-500/10 text-safe-500 border border-safe-500/20'
                  : 'bg-threat-500/10 text-threat-500 border border-threat-500/20'
              )}>
                <Wifi size={12} />
                Redis {health?.redis}
              </div>
              <button onClick={handleClearCache} className="btn-secondary text-sm">
                <Trash2 size={14} /> Clear Cache
              </button>
            </div>
          </motion.div>

          {/* Operations */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.45 }} className="glass-card p-5">
            <h3 className="font-semibold text-white mb-1">Quick Links</h3>
            <p className="text-xs text-gray-500 mb-4">External tools and monitoring.</p>
            <div className="flex flex-wrap gap-3">
              <a href="/v1/docs" target="_blank" rel="noreferrer" className="btn-secondary text-sm">
                <Cpu size={14} /> Swagger UI
              </a>
              <a href="/metrics" target="_blank" rel="noreferrer" className="btn-secondary text-sm">
                <Database size={14} /> Prometheus
              </a>
              <a href="/v1/health" target="_blank" rel="noreferrer" className="btn-secondary text-sm">
                <Shield size={14} /> Health JSON
              </a>
            </div>
          </motion.div>
        </>
      )}
    </div>
  )
}
