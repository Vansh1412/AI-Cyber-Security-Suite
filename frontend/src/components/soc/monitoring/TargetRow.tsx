/**
 * frontend/src/components/soc/monitoring/TargetRow.tsx
 * ─────────────────────────────────────────────────────
 * Renders an individual Monitored Target row with operational status badge,
 * telemetry indicators, and lifecycle action controls (Check Now, Pause/Resume, Reactivate, Delete).
 */

import React from 'react'
import {
  Clock,
  Eye,
  Globe,
  Loader2,
  Pause,
  Play,
  RotateCcw,
  Trash2,
  Zap,
} from 'lucide-react'
import type { MonitoringTarget } from '@/types/soc'
import { TargetStatusBadge } from './TargetStatusBadge'

export interface TargetRowProps {
  target: MonitoringTarget
  onSelect: (target: MonitoringTarget) => void
  onCheckNow: (target: MonitoringTarget) => void
  onTogglePauseResume: (target: MonitoringTarget) => void
  onReactivate: (target: MonitoringTarget) => void
  onDelete: (target: MonitoringTarget) => void
  isCheckingNow: boolean
}

export function TargetRow({
  target,
  onSelect,
  onCheckNow,
  onTogglePauseResume,
  onReactivate,
  onDelete,
  isCheckingNow,
}: TargetRowProps) {
  const isSuspended = !target.is_active && target.consecutive_failures >= 5
  const isActive = target.is_active

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return 'Pending check'
    try {
      return new Date(dateStr).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return dateStr
    }
  }

  const getPredictionBadge = (pred?: string | null, conf?: number | null) => {
    if (!pred) return null
    const norm = pred.toUpperCase()
    const confPct = conf ? Math.round(conf * 100) : null

    if (norm === 'MALICIOUS') {
      return (
        <span className="text-3xs font-semibold px-2 py-0.5 rounded-md bg-rose-500/15 text-rose-400 border border-rose-500/30">
          Malicious {confPct ? `(${confPct}%)` : ''}
        </span>
      )
    }
    if (norm === 'SUSPICIOUS') {
      return (
        <span className="text-3xs font-semibold px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-400 border border-amber-500/30">
          Suspicious {confPct ? `(${confPct}%)` : ''}
        </span>
      )
    }
    return (
      <span className="text-3xs font-semibold px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        Benign {confPct ? `(${confPct}%)` : ''}
      </span>
    )
  }

  return (
    <tr
      onClick={() => onSelect(target)}
      className="group border-b border-light-border dark:border-dark-border/60 hover:bg-light-hover/60 dark:hover:bg-dark-hover/40 transition-colors cursor-pointer text-xs"
    >
      {/* Status */}
      <td className="py-3 px-4 whitespace-nowrap">
        <TargetStatusBadge
          isActive={target.is_active}
          consecutiveFailures={target.consecutive_failures}
        />
      </td>

      {/* Target URL & Domain */}
      <td className="py-3 px-4 max-w-xs md:max-w-md">
        <div className="flex items-center gap-2">
          <Globe size={14} className="text-gray-400 shrink-0" />
          <span className="font-semibold text-gray-900 dark:text-gray-100 group-hover:text-primary-400 transition-colors truncate">
            {target.normalized_domain || target.url}
          </span>
        </div>
        <p className="text-3xs text-gray-500 font-mono truncate mt-0.5 max-w-sm pl-5">
          {target.url}
        </p>
      </td>

      {/* Interval */}
      <td className="py-3 px-4 whitespace-nowrap text-gray-600 dark:text-gray-300">
        <div className="flex items-center gap-1 font-mono">
          <Clock size={12} className="text-gray-400" />
          <span>Every {target.check_interval_minutes}m</span>
        </div>
      </td>

      {/* Last Execution Telemetry */}
      <td className="py-3 px-4 whitespace-nowrap">
        <div className="space-y-1">
          <div className="flex items-center gap-1.5">
            {getPredictionBadge(target.last_prediction, target.last_confidence)}
            {target.last_status_code && (
              <span className="text-3xs font-mono text-gray-400">
                HTTP {target.last_status_code}
              </span>
            )}
          </div>
          <p className="text-3xs text-gray-400">
            {formatDate(target.last_checked_at)}
          </p>
        </div>
      </td>

      {/* Next Scheduled Check */}
      <td className="py-3 px-4 whitespace-nowrap text-2xs text-gray-500 font-mono">
        {target.is_active ? formatDate(target.next_check_at) : 'Suspended / Paused'}
      </td>

      {/* Actions */}
      <td
        className="py-3 px-4 whitespace-nowrap text-right"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-end gap-1.5 opacity-90 group-hover:opacity-100 transition-opacity">
          {/* Check Now */}
          {target.is_active && (
            <button
              type="button"
              onClick={() => onCheckNow(target)}
              disabled={isCheckingNow}
              title="Trigger Immediate Check"
              className="p-1.5 text-gray-400 hover:text-primary-400 hover:bg-primary-500/10 rounded-lg transition-colors"
            >
              {isCheckingNow ? (
                <Loader2 size={14} className="animate-spin text-primary-500" />
              ) : (
                <Zap size={14} />
              )}
            </button>
          )}

          {/* Pause / Resume */}
          {!isSuspended && (
            <button
              type="button"
              onClick={() => onTogglePauseResume(target)}
              title={isActive ? 'Pause Target' : 'Resume Target'}
              className="p-1.5 text-gray-400 hover:text-amber-400 hover:bg-amber-500/10 rounded-lg transition-colors"
            >
              {isActive ? <Pause size={14} /> : <Play size={14} />}
            </button>
          )}

          {/* Reactivate (Displayed prominently if suspended or failing) */}
          {(isSuspended || target.consecutive_failures > 0) && (
            <button
              type="button"
              onClick={() => onReactivate(target)}
              title="Reactivate and Reset Failures"
              className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition-colors"
            >
              <RotateCcw size={14} />
            </button>
          )}

          {/* View Diagnostics Drawer */}
          <button
            type="button"
            onClick={() => onSelect(target)}
            title="Inspect Target Diagnostics"
            className="p-1.5 text-gray-400 hover:text-white hover:bg-dark-hover rounded-lg transition-colors"
          >
            <Eye size={14} />
          </button>

          {/* Soft Delete */}
          <button
            type="button"
            onClick={() => onDelete(target)}
            title="Deactivate Target"
            className="p-1.5 text-gray-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </td>
    </tr>
  )
}
