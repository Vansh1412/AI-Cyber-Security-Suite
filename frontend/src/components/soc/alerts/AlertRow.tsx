/**
 * frontend/src/components/soc/alerts/AlertRow.tsx
 * ───────────────────────────────────────────────
 * Formatted table row for a single security alert with quick-triage actions.
 */

import React from 'react'
import {
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Flame,
  Layers,
  RotateCcw,
  XCircle,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Alert } from '@/types/soc'
import { SeverityBadge } from './SeverityBadge'
import { clsx } from 'clsx'

export interface AlertRowProps {
  alert: Alert
  isSelected: boolean
  onSelect: (alert: Alert) => void
  onAcknowledge: (alert: Alert) => void
  onResolve: (alert: Alert) => void
  onDismiss: (alert: Alert) => void
  onReopen: (alert: Alert) => void
  onEscalate: (alert: Alert) => void
  isAdmin?: boolean
}

export function AlertRow({
  alert,
  isSelected,
  onSelect,
  onAcknowledge,
  onResolve,
  onDismiss,
  onReopen,
  onEscalate,
  isAdmin = false,
}: AlertRowProps) {
  // Format relative or concise timestamp
  const formatTime = (isoString: string) => {
    try {
      const d = new Date(isoString)
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    } catch {
      return isoString
    }
  }

  const copyToClipboard = (text: string, e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(text)
    toast.success('Indicator copied to clipboard', { duration: 1500 })
  }

  // Safe external URL validation (strictly rejects javascript: and dangerous schemes)
  const isSafeUrl =
    alert.indicator_value.startsWith('http://') || alert.indicator_value.startsWith('https://')

  const getStatusBadge = () => {
    switch (alert.status) {
      case 'OPEN':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-2xs font-semibold bg-sky-500/10 text-sky-400 border border-sky-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
            OPEN
          </span>
        )
      case 'ACKNOWLEDGED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-2xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            CLAIMED
          </span>
        )
      case 'RESOLVED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-2xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 size={10} />
            RESOLVED
          </span>
        )
      case 'DISMISSED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-2xs font-semibold bg-gray-500/10 text-gray-400 border border-gray-500/20">
            <XCircle size={10} />
            DISMISSED
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-2xs font-semibold bg-gray-500/10 text-gray-400 border border-gray-500/20">
            {alert.status}
          </span>
        )
    }
  }

  return (
    <tr
      onClick={() => onSelect(alert)}
      className={clsx(
        'border-b border-dark-border/60 transition-colors cursor-pointer text-xs',
        isSelected ? 'bg-primary-600/10 hover:bg-primary-600/15' : 'hover:bg-dark-hover/60'
      )}
    >
      {/* 1. Severity */}
      <td className="px-3.5 py-3 whitespace-nowrap">
        <SeverityBadge severity={alert.severity} />
      </td>

      {/* 2. Status */}
      <td className="px-3 py-3 whitespace-nowrap">{getStatusBadge()}</td>

      {/* 3. Title & Detection Rule */}
      <td className="px-3 py-3 max-w-xs">
        <div className="flex items-center gap-1.5">
          <p className="font-semibold text-white truncate max-w-[220px]" title={alert.title}>
            {alert.title}
          </p>
          {alert.incident_id && (
            <span className="px-1.5 py-0.2 rounded text-3xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
              INC#{alert.incident_id}
            </span>
          )}
          {isAdmin && alert.user_id !== null && alert.user_id !== undefined && (
            <span className="px-1.5 py-0.2 rounded text-3xs font-mono text-gray-400 bg-dark-surface border border-dark-border" title={`Tenant ID: ${alert.user_id}`}>
              T#{alert.user_id}
            </span>
          )}
        </div>
        <p className="text-2xs text-gray-400 truncate mt-0.5 font-mono">{alert.rule_name}</p>
      </td>

      {/* 4. Indicator */}
      <td className="px-3 py-3 max-w-sm">
        <div className="flex items-center gap-1.5">
          <span className="px-1.5 py-0.2 text-3xs font-bold rounded bg-dark-surface text-gray-400 border border-dark-border shrink-0">
            {alert.indicator_type}
          </span>
          <span
            className="font-mono text-gray-200 truncate max-w-[200px]"
            title={alert.indicator_value}
          >
            {alert.indicator_value}
          </span>
          <button
            type="button"
            onClick={(e) => copyToClipboard(alert.indicator_value, e)}
            className="p-1 hover:text-white text-gray-500 rounded transition-colors shrink-0"
            title="Copy indicator"
          >
            <Copy size={11} />
          </button>
          {isSafeUrl && (
            <a
              href={alert.indicator_value}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="p-1 hover:text-primary-400 text-gray-500 rounded transition-colors shrink-0"
              title="Open link in new window"
            >
              <ExternalLink size={11} />
            </a>
          )}
        </div>
      </td>

      {/* 5. Occurrence Count (Dedup Indicator) */}
      <td className="px-3 py-3 text-center whitespace-nowrap">
        {alert.occurrence_count > 1 ? (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md font-mono text-2xs font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30"
            title={`Suppressed deduplication: observed ${alert.occurrence_count} times`}
          >
            <Layers size={10} />
            <span>×{alert.occurrence_count}</span>
          </span>
        ) : (
          <span className="text-gray-500 font-mono text-2xs">1</span>
        )}
      </td>

      {/* 6. Last Seen Timestamp */}
      <td className="px-3 py-3 whitespace-nowrap text-gray-400 font-mono text-2xs">
        <div className="flex items-center gap-1">
          <Clock size={11} className="text-gray-500" />
          <span>{formatTime(alert.last_seen_at)}</span>
        </div>
      </td>

      {/* 7. Quick Triage Actions */}
      <td className="px-3.5 py-3 whitespace-nowrap text-right">
        <div className="inline-flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
          {alert.status === 'OPEN' && (
            <button
              type="button"
              onClick={() => onAcknowledge(alert)}
              className="px-2 py-1 bg-primary-600/20 hover:bg-primary-600/30 text-primary-300 border border-primary-500/30 rounded-lg text-2xs font-medium transition-colors"
              title="Claim alert for active triage"
            >
              Claim
            </button>
          )}

          {(alert.status === 'OPEN' || alert.status === 'ACKNOWLEDGED') && (
            <>
              <button
                type="button"
                onClick={() => onResolve(alert)}
                className="px-2 py-1 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 rounded-lg text-2xs font-medium transition-colors"
                title="Resolve alert"
              >
                Resolve
              </button>
              <button
                type="button"
                onClick={() => onDismiss(alert)}
                className="px-2 py-1 bg-gray-500/15 hover:bg-gray-500/25 text-gray-300 border border-gray-500/30 rounded-lg text-2xs font-medium transition-colors"
                title="Dismiss as false positive or accepted risk"
              >
                Dismiss
              </button>
            </>
          )}

          {(alert.status === 'RESOLVED' || alert.status === 'DISMISSED') && (
            <button
              type="button"
              onClick={() => onReopen(alert)}
              className="inline-flex items-center gap-1 px-2 py-1 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 rounded-lg text-2xs font-medium transition-colors"
              title="Reopen alert to OPEN triage pool"
            >
              <RotateCcw size={10} />
              Reopen
            </button>
          )}

          {/* Escalate button */}
          <button
            type="button"
            onClick={() => onEscalate(alert)}
            className="inline-flex items-center gap-1 px-2 py-1 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 rounded-lg text-2xs font-medium transition-colors"
            title="Escalate alert to an Incident"
          >
            <Flame size={10} />
            Escalate
          </button>
        </div>
      </td>
    </tr>
  )
}
