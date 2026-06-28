import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Loader2, TrendingUp, Shield, AlertTriangle,
  Activity, Zap, Database, Network, Target, Binary
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  AreaChart, Area, XAxis, YAxis, BarChart, Bar,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
} from 'recharts'
import { clsx } from 'clsx'
import { scanService } from '@/services/scan'

const CLASS_COLORS = {
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

function ChartCard({ title, sub, children, delay = 0 }: {
  title: string; sub?: string; children: React.ReactNode; delay?: number
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="glass-card p-5"
    >
      <div className="mb-4">
        <h3 className="font-semibold text-white">{title}</h3>
        {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
      </div>
      {children}
    </motion.div>
  )
}

// ── USER ANALYTICS TAB ───────────────────────────────────────────────────────
function UserAnalytics() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: scanService.getStats,
    refetchInterval: 60_000,
  })

  if (isLoading) {
    return (
      <div className="min-h-[40vh] flex items-center justify-center">
        <Loader2 size={32} className="animate-spin text-primary-500" />
      </div>
    )
  }

  const byClass = (stats?.by_class ?? {}) as Record<string, number>
  const total   = stats?.total_scans ?? 0
  const daily   = stats?.daily_volume ?? []

  const pieData = Object.entries(byClass).map(([name, value]) => ({ name, value: value as number }))

  const threatClasses = ['phishing', 'malware', 'defacement'] as const
  const threatTotal = threatClasses.reduce((s, k) => s + (byClass[k] ?? 0), 0)
  const safeTotal   = byClass['legitimate'] ?? 0

  const radarData = [
    { subject: 'Phishing',   A: byClass['phishing']   ?? 0 },
    { subject: 'Malware',    A: byClass['malware']    ?? 0 },
    { subject: 'Defacement', A: byClass['defacement'] ?? 0 },
    { subject: 'Legitimate', A: byClass['legitimate'] ?? 0 },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Your Total Scans',  value: total,        icon: Activity,      color: 'text-primary-400',   bg: 'bg-primary-500/15' },
          { label: 'Threats Blocked',   value: threatTotal,  icon: AlertTriangle, color: 'text-threat-500',    bg: 'bg-threat-500/15' },
          { label: 'Safe URLs',         value: safeTotal,    icon: Shield,        color: 'text-safe-500',       bg: 'bg-safe-500/15' },
          { label: 'Your Threat Rate',  value: total > 0 ? `${((threatTotal/total)*100).toFixed(1)}%` : '—', icon: TrendingUp, color: 'text-suspicious-500', bg: 'bg-suspicious-500/15' },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }} className="stat-card">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">{s.label}</p>
                <p className="text-3xl font-bold text-white">{s.value}</p>
              </div>
              <div className={`w-10 h-10 rounded-xl ${s.bg} flex items-center justify-center`}>
                <s.icon size={20} className={s.color} />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <ChartCard title="Your Scan Distribution" sub="All-time breakdown by class" delay={0.1}>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} paddingAngle={3} dataKey="value">
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={CLASS_COLORS[entry.name as keyof typeof CLASS_COLORS] ?? '#555'} />
                    ))}
                  </Pie>
                  <Tooltip {...TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {pieData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: CLASS_COLORS[d.name as keyof typeof CLASS_COLORS] ?? '#555' }} />
                    <span className="text-xs text-gray-400 capitalize">{d.name}</span>
                    <span className="text-xs text-white font-medium ml-auto">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No personal scans yet</div>
          )}
        </ChartCard>

        <ChartCard title="Your Scan Volume Trend" sub="Daily scans over time" delay={0.15} >
          <div className="lg:col-span-2">
            {daily.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={daily} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#0f6aff" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#0f6aff" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" tick={{ fill: '#6e7781', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#6e7781', fontSize: 10 }} />
                  <Tooltip {...TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="count" stroke="#0f6aff" fill="url(#areaGrad)" strokeWidth={2} dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-48 flex items-center justify-center text-gray-500 text-sm">No personal scans yet</div>
            )}
          </div>
        </ChartCard>

        <ChartCard title="Your Threat Profile" sub="Relative class volumes" delay={0.2}>
          <ResponsiveContainer width="100%" height={200}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#21262d" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: '#6e7781', fontSize: 11 }} />
              <Radar dataKey="A" stroke="#0f6aff" fill="#0f6aff" fillOpacity={0.25} />
              <Tooltip {...TOOLTIP_STYLE} />
            </RadarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </div>
  )
}

// ── MODEL ANALYTICS TAB (Engine Stats) ───────────────────────────────────────
function ModelAnalytics() {
  const modelPie = [
    { name: 'legitimate', value: 90.0 },
    { name: 'phishing',   value: 5.7 },
    { name: 'defacement', value: 3.4 },
    { name: 'malware',    value: 0.8 },
  ]

  const featureImportance = [
    { name: 'url_length',        importance: 0.85 },
    { name: 'count_special_char', importance: 0.72 },
    { name: 'has_ip',            importance: 0.91 },
    { name: 'domain_entropy',    importance: 0.65 },
    { name: 'path_length',       importance: 0.45 },
  ]

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Training Dataset', value: '2.77M', icon: Database, color: 'text-primary-400', bg: 'bg-primary-500/15', sub: 'URLs' },
          { label: 'Extracted Features', value: '63', icon: Binary, color: 'text-accent-400', bg: 'bg-accent-500/15', sub: 'Per URL' },
          { label: 'Validation Accuracy', value: '95.2%', icon: Target, color: 'text-safe-500', bg: 'bg-safe-500/15', sub: 'Holdout set' },
          { label: 'Model Architecture', value: 'XGBoost', icon: Network, color: 'text-threat-500', bg: 'bg-threat-500/15', sub: 'Calibrated CV' },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }} className="stat-card">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-sm text-gray-400 mb-1">{s.label}</p>
                <p className="text-3xl font-bold text-white">{s.value}</p>
                <p className="text-xs text-gray-500 mt-1">{s.sub}</p>
              </div>
              <div className={`w-10 h-10 rounded-xl ${s.bg} flex items-center justify-center`}>
                <s.icon size={20} className={s.color} />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <ChartCard title="Dataset Distribution" sub="2,748,192 total training samples" delay={0.1}>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={modelPie} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value">
                {modelPie.map((entry, i) => (
                  <Cell key={i} fill={CLASS_COLORS[entry.name as keyof typeof CLASS_COLORS]} />
                ))}
              </Pie>
              <Tooltip {...TOOLTIP_STYLE} formatter={(value) => `${value}%`} />
            </PieChart>
          </ResponsiveContainer>
          <div className="grid grid-cols-2 gap-2 mt-4">
            {modelPie.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: CLASS_COLORS[d.name as keyof typeof CLASS_COLORS] }} />
                <span className="text-xs text-gray-400 capitalize">{d.name}</span>
                <span className="text-xs text-white font-medium ml-auto">{d.value}%</span>
              </div>
            ))}
          </div>
        </ChartCard>

        <ChartCard title="Global Feature Importance" sub="Top SHAP values across dataset" delay={0.2}>
          <div className="lg:col-span-2">
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={featureImportance} layout="vertical" margin={{ top: 5, right: 20, left: 40, bottom: 0 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" tick={{ fill: '#6e7781', fontSize: 11 }} width={100} />
                <Tooltip {...TOOLTIP_STYLE} />
                <Bar dataKey="importance" fill="#0f6aff" radius={[0, 4, 4, 0]} barSize={20} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>
      </div>
    </div>
  )
}

// ── MAIN ANALYTICS VIEW ──────────────────────────────────────────────────────
export default function Analytics() {
  const [tab, setTab] = useState<'user' | 'model'>('user')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Analytics</h2>
          <p className="text-gray-400 text-sm mt-0.5">Deep-dive into your scans and our ML engine.</p>
        </div>

        {/* Tab Toggle */}
        <div className="bg-dark-bg border border-dark-border p-1 rounded-xl flex gap-1">
          <button
            onClick={() => setTab('user')}
            className={clsx(
              'px-5 py-2 text-sm font-medium rounded-lg transition-all',
              tab === 'user' ? 'bg-primary-600 text-white shadow-lg' : 'text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
            )}
          >
            User Analytics
          </button>
          <button
            onClick={() => setTab('model')}
            className={clsx(
              'px-5 py-2 text-sm font-medium rounded-lg transition-all',
              tab === 'model' ? 'bg-accent-600 text-white shadow-lg' : 'text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
            )}
          >
            Model Analytics
          </button>
        </div>
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.2 }}
        >
          {tab === 'user' ? <UserAnalytics /> : <ModelAnalytics />}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}
