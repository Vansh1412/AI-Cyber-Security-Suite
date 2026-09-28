/**
 * frontend/src/components/soc/incidents/IncidentRow.tsx
 * ───────────────────────────────────────────────────────
 * Renders an individual Incident row with status badge, severity visualization,
 * linked alert count, assignee state, and contextual actions.
 */

import React from 'react'
import {
  Clock,
  Eye,
  Link2,
  RefreshCw,
  ShieldAlert,
  User as UserIcon,
} from 'lucide-react'
import type { Incident, IncidentStatus } from '@/types/soc'
import { SeverityBadge } from '@/components/soc/alerts/SeverityBadge'
import { clsx } from 'clsx'

export interface IncidentRowProps {
  incident: Incident
  onSelect: (incident: Incident) => void
  onStatusClick: (incident: Incident) => void
  onAttachAlertClick: (incident: Incident) => void
  currentUserId?: number
}

export function getIncidentStatusBadge(status: IncidentStatus | string) {
  const norm = (status || 'OPEN').toUpperCase()
  switch (norm) {
    case 'OPEN':
      return {
        label: 'Open',
        classes: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
        dot: 'bg-rose-400',
      }
    case 'INVESTIGATING':
      return {
        label: 'Investigating',
        classes: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
        dot: 'bg-amber-400',
      }
    case 'CONTAINED':
      return {
        label: 'Contained',
        classes: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
        dot: 'bg-purple-400',
      }
    case 'RESOLVED':
      return {
        label: 'Resolved',
        classes: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
        dot: 'bg-emerald-400',
      }
    case 'CLOSED':
      return {
        label: 'Closed',
        classes: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
        dot: 'bg-gray-400',
      }
    default:
      return {
        label: norm,
        classes: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
        dot: 'bg-gray-400',
      }
  }
}

export function IncidentRow({
  incident,
  onSelect,
  onStatusClick,
  onAttachAlertClick,
  currentUserId,
}: IncidentRowProps) {
  const statusConfig = getIncidentStatusBadge(incident.status)
  const isAssignedToCurrent =
    currentUserId && incident.assigned_to_user_id === currentUserId

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      const d = new Date(dateStr)
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return dateStr
    }
  }

  return (
    <tr
      onClick={() => onSelect(incident)}
      className="group border-b border-light-border dark:border-dark-border/60 hover:bg-light-hover/60 dark:hover:bg-dark-hover/40 transition-colors cursor-pointer text-xs"
    >
      {/* Severity */}
      <td className="py-3 px-4 whitespace-nowrap">
        <SeverityBadge severity={incident.severity} />
      </td>

      {/* Title & Description */}
      <td className="py-3 px-4 max-w-xs md:max-w-md">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-gray-900 dark:text-gray-100 group-hover:text-primary-400 transition-colors truncate">
            {incident.title}
          </span>
          <span className="font-mono text-3xs text-gray-400 shrink-0">
            #{incident.incident_uuid?.slice(0, 8) || incident.id}
          </span>
        </div>
        {incident.description && (
          <p className="text-2xs text-gray-500 dark:text-gray-400 truncate mt-0.5 max-w-sm">
            {incident.description}
          </p>
        )}
      </td>

      {/* Status */}
      <td className="py-3 px-4 whitespace-nowrap">
        <span
          className={clsx(
            'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border select-none',
            statusConfig.classes
          )}
        >
          <span className={clsx('h-1.5 w-1.5 rounded-full', statusConfig.dot)} />
          <span>{statusConfig.label}</span>
        </span>
      </td>

      {/* Linked Alerts */}
      <td className="py-3 px-4 whitespace-nowrap">
        <div className="flex items-center gap-1.5 text-gray-600 dark:text-gray-300">
          <ShieldAlert size={14} className="text-gray-400" />
          <span className="font-mono font-medium">
            {incident.alert_count ?? incident.alerts?.length ?? 0}
          </span>
          <span className="text-2xs text-gray-500">alerts</span>
        </div>
      </td>

      {/* Assignee */}
      <td className="py-3 px-4 whitespace-nowrap">
        <div className="flex items-center gap-1.5">
          <UserIcon size={13} className="text-gray-400 shrink-0" />
          {incident.assigned_to_user_id ? (
            <span
              className={clsx(
                'text-2xs font-medium px-2 py-0.5 rounded-md border',
                isAssignedToCurrent
                  ? 'bg-primary-500/10 text-primary-300 border-primary-500/30'
                  : 'bg-light-card dark:bg-dark-card text-gray-400 border-light-border dark:border-dark-border'
              )}
            >
              {isAssignedToCurrent ? 'You' : `User #${incident.assigned_to_user_id}`}
            </span>
          ) : (
            <span className="text-2xs text-gray-500 italic">Unassigned</span>
          )}
        </div>
      </td>

      {/* Created Timestamp */}
      <td className="py-3 px-4 whitespace-nowrap text-gray-500 text-2xs">
        <div className="flex items-center gap-1">
          <Clock size={12} className="text-gray-400" />
          <span>{formatDate(incident.created_at)}</span>
        </div>
      </td>

      {/* Contextual Actions */}
      <td
        className="py-3 px-4 whitespace-nowrap text-right"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-end gap-1.5 opacity-90 group-hover:opacity-100 transition-opacity">
          {/* Quick status transition trigger */}
          <button
            type="button"
            onClick={() => onStatusClick(incident)}
            title="Update Incident Status"
            className="p-1.5 text-gray-400 hover:text-amber-400 hover:bg-amber-500/10 rounded-lg transition-colors"
          >
            <RefreshCw size={14} />
          </button>

          {/* Quick attach alert trigger */}
          <button
            type="button"
            onClick={() => onAttachAlertClick(incident)}
            title="Attach Alerts"
            className="p-1.5 text-gray-400 hover:text-primary-400 hover:bg-primary-500/10 rounded-lg transition-colors"
          >
            <Link2 size={14} />
          </button>

          {/* Inspect details */}
          <button
            type="button"
            onClick={() => onSelect(incident)}
            title="View Details"
            className="p-1.5 text-gray-400 hover:text-white hover:bg-dark-hover rounded-lg transition-colors"
          >
            <Eye size={14} />
          </button>
        </div>
      </td>
    </tr>
  )
}
