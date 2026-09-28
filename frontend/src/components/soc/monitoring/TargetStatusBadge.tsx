/**
 * frontend/src/components/soc/monitoring/TargetStatusBadge.tsx
 * ────────────────────────────────────────────────────────────
 * Renders the authoritative operational status badge for a monitored target:
 * - Active / Healthy (is_active=true, failures=0)
 * - Failing / Degraded (is_active=true, failures > 0)
 * - Paused (is_active=false, failures < 5)
 * - Suspended (is_active=false, failures >= 5)
 */

import React from 'react'
import { clsx } from 'clsx'

export interface TargetStatusBadgeProps {
  isActive: boolean
  consecutiveFailures: number
  className?: string
  showDot?: boolean
}

export type TargetStateCategory =
  | 'ACTIVE_HEALTHY'
  | 'ACTIVE_FAILING'
  | 'PAUSED'
  | 'SUSPENDED'

export function getTargetStateCategory(
  isActive: boolean,
  failures: number
): TargetStateCategory {
  if (isActive) {
    return failures > 0 ? 'ACTIVE_FAILING' : 'ACTIVE_HEALTHY'
  }
  return failures >= 5 ? 'SUSPENDED' : 'PAUSED'
}

export function TargetStatusBadge({
  isActive,
  consecutiveFailures,
  className,
  showDot = true,
}: TargetStatusBadgeProps) {
  const category = getTargetStateCategory(isActive, consecutiveFailures)

  const getConfig = () => {
    switch (category) {
      case 'ACTIVE_HEALTHY':
        return {
          label: 'Active',
          classes: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
          dot: 'bg-emerald-400',
          pulse: false,
        }
      case 'ACTIVE_FAILING':
        return {
          label: `Failing (${consecutiveFailures})`,
          classes: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
          dot: 'bg-amber-400',
          pulse: true,
        }
      case 'SUSPENDED':
        return {
          label: 'Suspended',
          classes: 'text-rose-400 bg-rose-500/15 border-rose-500/30',
          dot: 'bg-rose-400',
          pulse: true,
        }
      case 'PAUSED':
      default:
        return {
          label: 'Paused',
          classes: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
          dot: 'bg-gray-400',
          pulse: false,
        }
    }
  }

  const config = getConfig()

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border select-none tracking-wide uppercase',
        config.classes,
        className
      )}
    >
      {showDot && (
        <span className="relative flex h-1.5 w-1.5">
          {config.pulse && (
            <span
              className={clsx(
                'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
                config.dot
              )}
            />
          )}
          <span className={clsx('relative inline-flex rounded-full h-1.5 w-1.5', config.dot)} />
        </span>
      )}
      <span>{config.label}</span>
    </span>
  )
}
