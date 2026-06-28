import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, TrendingUp, Activity, Clock,
  AlertTriangle, CheckCircle, Loader2, ExternalLink,
  RefreshCw, Zap, Wifi, Database
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis,
} from 'recharts'
import { useAuth } from '@/contexts/AuthContext'
import { scanService } from '@/services/scan'
import { clsx } from 'clsx'
import type { PredictionClass } from '@/types'

const CLASS_COLORS: Record<PredictionClass, string> = {
  legitimate:  '#22c55e',
  phishing:    '#ef4444',
  malware:     '#f97316',
  defacement:  '#f59e0b',
}

const TOOLTIP_STYLE = {
  contentStyle: {
    background: '#161b22',
    border: '1px solid #21262d',
    borderRadius: '12px',
    color: '#fff',
    fontSize: '12px',
  }
}

// ── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ title, value, sub, icon: Icon, iconBg, iconColor, trend, delay = 0 }: {
  title: string; value: string | number; sub: string; icon: React.ElementType
  iconBg: string; iconColor: string; trend?: string; delay?: number
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="stat-card"
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-gray-400 mb-1 uppercase tracking-wider">{title}</p>
          <p className="text-3xl font-black text-white">{value}</p>
          {trend && (
            <p className="text-xs text-safe-500 mt-0.5 flex items-center gap-1">
              <TrendingUp size={11} /> {trend}
            </p>
          )}
          <p className="text-xs text-gray-500 mt-1">{sub}</p>
        </div>
        <div className={clsx('w-11 h-11 rounded-xl flex items-center justify-center', iconBg)}>
          <Icon size={20} className={iconColor} />
        </div>
      </div>
    </motion.div>
  )
}

// ── Recent item ──────────────────────────────────────────────────────────────
function RecentItem({ url, prediction, confidence, time, onClick }: {
  url: string; prediction: PredictionClass; confidence: number; time: string; onClick: () => void
}) {
  const safe = prediction === 'legitimate'
  return (
    <div
      onClick={onClick}
      className="flex items-center gap-3 py-3 border-b border-dark-border last:border-0 hover:bg-dark-hover cursor-pointer px-1 rounded-lg transition-colors -mx-1"
    >
      <div className={clsx('w-8 h-8 rounded-full flex items-center justify-center shrink-0', safe ? 'bg-safe-500/15' : 'bg-threat-500/15')}>
        {safe
          ? <CheckCircle size={14} className="text-safe-500" />
          : <AlertTriangle size={14} className="text-threat-500" />
        }
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white font-mono truncate">{url}</p>
        <p className="text-xs text-gray-500">{time}</p>
      </div>
      <div className="text-right shrink-0">
        <span className={safe ? 'badge-safe' : 'badge-phishing'}>
          {safe ? 'Safe' : prediction}
        </span>
        <p className="text-xs text-gray-500 mt-0.5">{(confidence * 100).toFixed(1)}%</p>
      </div>
    </div>
  )
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const { user } = useAuth()

  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['stats'],
    queryFn: scanService.getStats,
    refetchInterval: 30_000,
    retry: 1,
  })

  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: scanService.getHealth,
    refetchInterval: 30_000,
    retry: 1,
  })

  const { data: history, isLoading: histLoading } = useQuery({
    queryKey: ['history', 1, 5],
    queryFn: () => scanService.getHistory(1, 5),
    refetchInterval: 30_000,
    retry: 1,
  })

  const byClass   = (stats?.by_class ?? {}) as Record<string, number>
  const total     = stats?.total_scans ?? 0
  const threats   = (byClass['phishing'] ?? 0) + (byClass['malware'] ?? 0) + (byClass['defacement'] ?? 0)
  const dailyVol  = stats?.daily_volume ?? []
  const todayVol  = dailyVol.length > 0 ? dailyVol[dailyVol.length - 1]?.count ?? 0 : 0
  
  // Compute average latency from recent history
  const avgLatency = history?.length
    ? (history.reduce((s, h) => s + (h.latency_ms ?? 0), 0) / history.length).toFixed(1)
    : '—'

  const pieData = Object.entries(byClass).map(([name, value]) => ({ name, value: value as number }))

  // Dynamic Greeting
  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good Morning' : hour < 18 ? 'Good Afternoon' : 'Good Evening'
  const name = user?.email?.split('@')[0] ?? 'User'

  // Dynamic Subtext
  let subtext = 'Your protection status is Healthy. No threats detected today.'
  const recentThreats = history?.filter(h => h.prediction !== 'legitimate' && new Date(h.created_at).toDateString() === new Date().toDateString()).length ?? 0
  if (todayVol > 0) {
    if (recentThreats > 0) {
      subtext = `Today you've scanned ${todayVol} websites. ${recentThreats} ${recentThreats === 1 ? 'was' : 'were'} suspicious.`
    } else {
      subtext = `Today you've scanned ${todayVol} websites. No threats detected.`
    }
  }

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white">
            {greeting}, <span className="gradient-text">{name}</span> 👋
          </h2>
          <p className="text-gray-400 text-sm mt-0.5">
            {subtext}
          </p>
        </div>
        <button onClick={() => refetchStats()} className="btn-ghost text-sm">
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Scans"      value={total}            sub="Your account"      icon={Activity}    iconBg="bg-primary-500/15"    iconColor="text-primary-400"   delay={0.0} />
        <StatCard title="Today's Scans"    value={todayVol}         sub="Last 24 hours"     icon={TrendingUp}  iconBg="bg-safe-500/15"       iconColor="text-safe-500"      delay={0.07} />
        <StatCard title="Threats Detected" value={threats}          sub="Across your scans" icon={Shield}      iconBg="bg-threat-500/15"     iconColor="text-threat-500"    delay={0.14} />
        <StatCard title="Avg Scan Time"    value={`${avgLatency}ms`} sub="Recent scans"      icon={Clock}       iconBg="bg-accent-500/15"     iconColor="text-accent-400"    delay={0.21} />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Pie */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="glass-card p-5">
          <h3 className="font-semibold text-white mb-4">Threat Distribution</h3>
          <p className="text-xs text-gray-500 mb-2 -mt-2">(your scans only)</p>
          {statsLoading ? (
            <div className="h-48 flex items-center justify-center"><Loader2 size={22} className="animate-spin text-gray-500" /></div>
          ) : pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={170}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={78} paddingAngle={4} dataKey="value">
                    {pieData.map((e, i) => <Cell key={i} fill={CLASS_COLORS[e.name as PredictionClass] ?? '#555'} />)}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-1.5 mt-2">
                {pieData.map(d => (
                  <div key={d.name} className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CLASS_COLORS[d.name as PredictionClass] ?? '#555' }} />
                    <span className="text-xs text-gray-400 capitalize">{d.name}</span>
                    <span className="text-xs text-white font-semibold ml-auto">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No data yet</div>
          )}
        </motion.div>

        {/* Area chart - scans over time */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }} className="glass-card p-5 lg:col-span-2">
          <h3 className="font-semibold text-white mb-4">Scans This Week</h3>
          <p className="text-xs text-gray-500 mb-2 -mt-2">(your recent activity)</p>
          {statsLoading ? (
            <div className="h-48 flex items-center justify-center"><Loader2 size={22} className="animate-spin text-gray-500" /></div>
          ) : (stats?.daily_volume?.length ?? 0) > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={stats!.daily_volume} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="dashGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#0f6aff" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#0f6aff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#6e7781', fontSize: 10 }} />
                <YAxis tick={{ fill: '#6e7781', fontSize: 10 }} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="count" stroke="#0f6aff" fill="url(#dashGrad)" strokeWidth={2.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">
              No scans yet. <a href="/scan" className="text-primary-400 ml-1 hover:underline">Scan your first URL →</a>
            </div>
          )}
        </motion.div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Recent activity */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="glass-card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold text-white">Recent Activity</h3>
            <a href="/history" className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1">
              View all <ExternalLink size={11} />
            </a>
          </div>
          {histLoading ? (
            <div className="h-24 flex items-center justify-center"><Loader2 size={20} className="animate-spin text-gray-500" /></div>
          ) : (history?.length ?? 0) > 0 ? (
            history!.map(item => (
              <RecentItem
                key={item.id}
                url={item.url}
                prediction={item.prediction}
                confidence={item.confidence}
                time={new Date(item.created_at).toLocaleString()}
                onClick={() => { window.location.href = '/history' }}
              />
            ))
          ) : (
            <div className="h-24 flex items-center justify-center text-gray-500 text-sm">
              No recent scans. <a href="/scan" className="text-primary-400 ml-1 hover:underline">Start scanning →</a>
            </div>
          )}
        </motion.div>

        {/* System health mini */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="glass-card p-5">
          <h3 className="font-semibold text-white mb-4">System Health</h3>
          <div className="space-y-3">
            {[
              { label: 'Database', value: health?.database, icon: Database },
              { label: 'Redis',    value: health?.redis,    icon: Wifi },
              { label: 'Model',    value: health?.model,    icon: Zap },
            ].map(({ label, value, icon: Icon }) => {
              const ok = ['connected', 'loaded'].includes(value ?? '')
              return (
                <div key={label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon size={14} className="text-gray-500" />
                    <span className="text-sm text-gray-300">{label}</span>
                  </div>
                  <span className={clsx('flex items-center gap-1.5 text-xs font-semibold', ok ? 'text-safe-500' : 'text-threat-500')}>
                    <span className={clsx('w-1.5 h-1.5 rounded-full', ok ? 'bg-safe-500 animate-pulse' : 'bg-threat-500')} />
                    {value ?? 'unknown'}
                  </span>
                </div>
              )
            })}
            <div className="pt-2 border-t border-dark-border">
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-500">Memory</span>
                <span className="text-xs text-white font-mono">{health?.memory ?? '—'}</span>
              </div>
            </div>
          </div>
          <a href="/admin" className="btn-ghost text-xs w-full justify-center mt-4">
            Full Admin Panel <ExternalLink size={11} />
          </a>
        </motion.div>
      </div>
    </div>
  )
}
