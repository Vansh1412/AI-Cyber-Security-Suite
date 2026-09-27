/**
 * frontend/src/components/soc/alerts/SeverityBadge.tsx
 * ────────────────────────────────────────────────────
 * Visual badge for EventSeverity levels (INFO, LOW, MEDIUM, HIGH, CRITICAL).
 */

import React from 'react'
import { clsx } from 'clsx'
import type { EventSeverity } from '@/types/soc'

export interface SeverityBadgeProps {
  severity: EventSeverity | string
  className?: string
  showDot?: boolean
}

export function SeverityBadge({
  severity,
  className,
  showDot = true,
}: SeverityBadgeProps) {
  const normalized = (severity || 'INFO').toUpperCase()

  const getConfig = () => {
    switch (normalized) {
      case 'CRITICAL':
        return {
          label: 'CRITICAL',
          classes: 'text-rose-400 bg-rose-500/15 border-rose-500/30',
          dot: 'bg-rose-400',
          pulse: true,
        }
      case 'HIGH':
        return {
          label: 'HIGH',
          classes: 'text-amber-400 bg-amber-500/15 border-amber-500/30',
          dot: 'bg-amber-400',
          pulse: false,
        }
      case 'MEDIUM':
        return {
          label: 'MEDIUM',
          classes: 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30',
          dot: 'bg-yellow-400',
          pulse: false,
        }
      case 'LOW':
        return {
          label: 'LOW',
          classes: 'text-sky-400 bg-sky-500/15 border-sky-500/30',
          dot: 'bg-sky-400',
          pulse: false,
        }
      case 'INFO':
      default:
        return {
          label: normalized,
          classes: 'text-gray-400 bg-gray-500/15 border-gray-500/30',
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
