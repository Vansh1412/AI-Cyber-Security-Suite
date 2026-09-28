/**
 * frontend/src/components/soc/monitoring/MonitoringStatsBar.tsx
 * ─────────────────────────────────────────────────────────────
 * KPI and fleet telemetry statistics bar for Target Monitoring.
 * Powered by backend GET /v1/monitor/stats endpoint.
 */

import React from 'react'
import {
  Activity,
  AlertTriangle,
  Cpu,
  Layers,
  PauseCircle,
  XCircle,
} from 'lucide-react'
import type { MonitoringStatsResponse } from '@/types/soc'

export interface MonitoringStatsBarProps {
  stats: MonitoringStatsResponse | undefined
  isLoading: boolean
  userRole?: string
}

export function MonitoringStatsBar({
  stats,
  isLoading,
  userRole,
}: MonitoringStatsBarProps) {
  const isAdmin = userRole === 'admin'
  const quota = isAdmin ? 500 : 20

  if (isLoading || !stats) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="h-20 bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl animate-pulse"
          />
        ))}
      </div>
    )
  }

  const cards = [
    {
      label: 'Total Fleet',
      value: stats.total_targets,
      icon: Layers,
      color: 'text-primary-500 dark:text-primary-400',
      badge: `${stats.active_targets}/${quota} Active`,
    },
    {
      label: 'Active Probes',
      value: stats.active_targets,
      icon: Activity,
      color: 'text-emerald-500 dark:text-emerald-400',
      badge: 'Scheduled',
    },
    {
      label: 'Paused Targets',
      value: stats.paused_targets,
      icon: PauseCircle,
      color: 'text-gray-400',
      badge: 'Inactive',
    },
    {
      label: 'Auto-Suspended',
      value: stats.suspended_targets,
      icon: XCircle,
      color: 'text-rose-500 dark:text-rose-400',
      badge: '>= 5 Failures',
    },
    {
      label: 'Failing / Degraded',
      value: stats.failing_targets,
      icon: AlertTriangle,
      color: 'text-amber-500 dark:text-amber-400',
      badge: 'Needs Review',
    },
    {
      label: 'Worker Pool',
      value: `${stats.active_workers} / ${stats.pool_capacity}`,
      icon: Cpu,
      color: 'text-sky-500 dark:text-sky-400',
      badge: stats.scheduler_leader ? 'Leader Active' : 'Idle',
    },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, idx) => (
        <div
          key={idx}
          className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-3.5 flex flex-col justify-between shadow-2xs hover:border-light-border/80 dark:hover:border-dark-border/80 transition-colors"
        >
          <div className="flex items-center justify-between text-2xs text-gray-500">
            <span className="font-semibold uppercase tracking-wider">{card.label}</span>
            <card.icon size={15} className={card.color} />
          </div>

          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-xl font-bold font-mono text-gray-900 dark:text-white tracking-tight">
              {card.value}
            </span>
            <span className="text-3xs font-medium px-1.5 py-0.5 rounded-md bg-light-hover dark:bg-dark-surface text-gray-500 border border-light-border dark:border-dark-border">
              {card.badge}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}
