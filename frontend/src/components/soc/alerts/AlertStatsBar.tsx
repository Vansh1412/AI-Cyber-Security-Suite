/**
 * frontend/src/components/soc/alerts/AlertStatsBar.tsx
 * ────────────────────────────────────────────────────
 * Telemetry and KPI summary cards for the SOC Alert Console.
 */

import React from 'react'
import { motion } from 'framer-motion'
import { Activity, AlertOctagon, CheckCircle2, Layers, ShieldAlert } from 'lucide-react'
import type { AlertStatsResponse } from '@/types/soc'
import { clsx } from 'clsx'

export interface AlertStatsBarProps {
  stats: AlertStatsResponse | undefined
  isLoading: boolean
  error?: string | null
}

export function AlertStatsBar({ stats, isLoading, error }: AlertStatsBarProps) {
  if (error) {
    return (
      <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
        <AlertOctagon size={16} className="text-rose-400 shrink-0" />
        <span>Telemetry Unavailable: Failed to load real-time alert statistics.</span>
      </div>
    )
  }

  const cards = [
    {
      title: 'Total Alerts',
      value: stats ? stats.total_alerts.toLocaleString() : '—',
      sub: stats ? `${stats.alerts_last_24h} in last 24h` : 'Historical baseline',
      icon: ShieldAlert,
      iconBg: 'bg-primary-500/15',
      iconColor: 'text-primary-400',
    },
    {
      title: 'Open Triage Pool',
      value: stats ? stats.open_alerts.toLocaleString() : '—',
      sub: stats
        ? `${stats.acknowledged_alerts} currently claimed`
        : 'Awaiting analyst triage',
      icon: AlertOctagon,
      iconBg: 'bg-rose-500/15',
      iconColor: 'text-rose-400',
      pulse: !!(stats && stats.open_alerts > 0),
    },
    {
      title: 'Remediated & Closed',
      value: stats
        ? (stats.resolved_alerts + stats.dismissed_alerts).toLocaleString()
        : '—',
      sub: stats
        ? `${stats.resolved_alerts} resolved • ${stats.dismissed_alerts} dismissed`
        : 'Completed triage',
      icon: CheckCircle2,
      iconBg: 'bg-emerald-500/15',
      iconColor: 'text-emerald-400',
    },
    {
      title: 'Alert Velocity',
      value: stats ? `${stats.alert_velocity_per_hour.toFixed(1)}/hr` : '—',
      sub: 'Rolling ingestion rate',
      icon: Activity,
      iconBg: 'bg-amber-500/15',
      iconColor: 'text-amber-400',
    },
    {
      title: 'Dedup Savings',
      value: stats ? `${(stats.dedup_savings_ratio * 100).toFixed(0)}%` : '—',
      sub: 'Storm noise suppressed',
      icon: Layers,
      iconBg: 'bg-purple-500/15',
      iconColor: 'text-purple-400',
    },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
      {cards.map((card, idx) => {
        const Icon = card.icon
        return (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.04 }}
            className="stat-card"
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-2xs font-semibold text-gray-400 uppercase tracking-wider mb-1">
                  {card.title}
                </p>
                {isLoading ? (
                  <div className="h-7 w-16 bg-white/5 animate-pulse rounded my-1" />
                ) : (
                  <p className="text-2xl font-black text-white tracking-tight">
                    {card.value}
                  </p>
                )}
                <p className="text-2xs text-gray-500 mt-1 truncate">{card.sub}</p>
              </div>
              <div
                className={clsx(
                  'w-9 h-9 rounded-xl flex items-center justify-center shrink-0',
                  card.iconBg
                )}
              >
                <Icon size={18} className={card.iconColor} />
              </div>
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}
