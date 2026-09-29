/**
 * frontend/src/components/soc/containment/ContainmentActionRow.tsx
 * ──────────────────────────────────────────────────────────────
 * Renders an individual SOAR Containment Action row with typed status badges,
 * Rule 0 allowlist indicators, target references, and safe rollback controls.
 */

import React from 'react'
import {
  AlertOctagon,
  Ban,
  Bell,
  Clock,
  Eye,
  Radio,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { ContainmentActionResponse } from '@/types/soc'

export interface ContainmentActionRowProps {
  action: ContainmentActionResponse
  onSelect: (action: ContainmentActionResponse) => void
  onRevert: (action: ContainmentActionResponse) => void
  isReverting?: boolean
}

export function ContainmentActionRow({
  action,
  onSelect,
  onRevert,
  isReverting = false,
}: ContainmentActionRowProps) {
  // Provenance check: only specific actions can be reverted
  const isReversible =
    action.status === 'EXECUTED' &&
    (action.action_type === 'BLACKLIST_INDICATOR' || action.action_type === 'QUARANTINE_TARGET')

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return '—'
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

  const renderActionTypeBadge = (type: string) => {
    switch (type) {
      case 'BLACKLIST_INDICATOR':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Ban size={13} />
            Blacklist
          </span>
        )
      case 'QUARANTINE_TARGET':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <ShieldX size={13} />
            Quarantine
          </span>
        )
      case 'INVALIDATE_CACHE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <RefreshCw size={13} />
            Cache Purge
          </span>
        )
      case 'CREATE_INCIDENT':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <AlertOctagon size={13} />
            Incident
          </span>
        )
      case 'EMIT_SOC_EVENT':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Radio size={13} />
            SOC Event
          </span>
        )
      case 'SEND_NOTIFICATION':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Bell size={13} />
            Notification
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20">
            {type}
          </span>
        )
    }
  }

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'EXECUTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck size={12} />
            Executed
          </span>
        )
      case 'BLOCKED_BY_ALLOWLIST':
        return (
          <span
            className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-300 border border-amber-500/30"
            title="Rule 0 allowlist invariant prevented containment of a trusted resource"
          >
            <ShieldAlert size={12} className="text-amber-400" />
            Allowlisted
          </span>
        )
      case 'REVERTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <RotateCcw size={12} />
            Reverted
          </span>
        )
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            Failed
          </span>
        )
      case 'PENDING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
            Pending
          </span>
        )
      case 'SKIPPED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-500/10 text-gray-400 border border-gray-500/20">
            Skipped
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-500/10 text-gray-400">
            {status}
          </span>
        )
    }
  }

  return (
    <tr
      className="border-b border-light-border dark:border-dark-border hover:bg-gray-50 dark:hover:bg-dark-hover/40 transition-colors cursor-pointer"
      onClick={() => onSelect(action)}
    >
      {/* Action Type & UUID */}
      <td className="py-3.5 px-4">
        <div className="flex flex-col gap-1">
          <div>{renderActionTypeBadge(action.action_type)}</div>
          <span className="text-2xs font-mono text-gray-400">
            {action.action_uuid.substring(0, 8)}...
          </span>
        </div>
      </td>

      {/* Target Identifier */}
      <td className="py-3.5 px-4 max-w-xs">
        <div className="flex items-center gap-1.5 truncate">
          <span
            className="text-sm font-mono font-medium text-gray-900 dark:text-white truncate"
            title={action.target_identifier}
          >
            {action.target_identifier}
          </span>
        </div>
        {action.error_message && (
          <p
            className="text-2xs text-rose-400 truncate mt-0.5"
            title={action.error_message}
          >
            {action.error_message}
          </p>
        )}
      </td>

      {/* Operational Status */}
      <td className="py-3.5 px-4">{renderStatusBadge(action.status)}</td>

      {/* Trigger Source & References */}
      <td className="py-3.5 px-4 text-xs text-gray-600 dark:text-gray-400">
        <div className="flex flex-col gap-0.5">
          <span className="capitalize">{action.trigger_source.replace(/_/g, ' ')}</span>
          {action.alert_id && (
            <span className="text-2xs text-primary-400">Alert #{action.alert_id}</span>
          )}
          {action.incident_id && (
            <span className="text-2xs text-purple-400">Incident #{action.incident_id}</span>
          )}
        </div>
      </td>

      {/* Created Timestamp */}
      <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
        <div className="flex items-center gap-1">
          <Clock size={12} className="text-gray-400" />
          <span>{formatDate(action.created_at)}</span>
        </div>
      </td>

      {/* Action Controls */}
      <td
        className="py-3.5 px-4 text-right whitespace-nowrap"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-end gap-1.5">
          <button
            type="button"
            onClick={() => onSelect(action)}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
            title="View Details"
            aria-label="View action details"
          >
            <Eye size={15} />
          </button>

          {isReversible && (
            <button
              type="button"
              disabled={isReverting}
              onClick={() => onRevert(action)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-semibold bg-purple-500/10 text-purple-400 hover:bg-purple-500/20 border border-purple-500/20 transition-all disabled:opacity-50"
              title="Rollback action"
              aria-label="Revert containment action"
            >
              <RotateCcw size={12} className={isReverting ? 'animate-spin' : ''} />
              Revert
            </button>
          )}
        </div>
      </td>
    </tr>
  )
}
