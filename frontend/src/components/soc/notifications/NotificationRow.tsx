/**
 * frontend/src/components/soc/notifications/NotificationRow.tsx
 * ─────────────────────────────────────────────────────────────
 * Renders an individual in-app notification row with severity badge,
 * read/unread state dot, message preview, and quick mark-read control.
 */

import React from 'react'
import {
  AlertCircle,
  AlertTriangle,
  Check,
  Clock,
  Eye,
  Info,
  Loader2,
} from 'lucide-react'
import type { NotificationItem } from '@/types/soc'

export interface NotificationRowProps {
  notification: NotificationItem
  onSelect: (notification: NotificationItem) => void
  onMarkRead: (uuid: string) => void
  isMarkingRead?: boolean
}

export function NotificationRow({
  notification,
  onSelect,
  onMarkRead,
  isMarkingRead = false,
}: NotificationRowProps) {
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

  const renderSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertTriangle size={11} />
            CRITICAL
          </span>
        )
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertCircle size={11} />
            HIGH
          </span>
        )
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">
            MEDIUM
          </span>
        )
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
            LOW
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20">
            <Info size={11} />
            INFO
          </span>
        )
    }
  }

  return (
    <tr
      className={`border-b border-light-border dark:border-dark-border hover:bg-gray-50 dark:hover:bg-dark-hover/40 transition-colors cursor-pointer ${
        !notification.is_read ? 'bg-primary-500/[0.03] dark:bg-primary-500/[0.02]' : ''
      }`}
      onClick={() => onSelect(notification)}
    >
      {/* Unread Status Dot */}
      <td className="py-3.5 px-4 w-6 text-center">
        {!notification.is_read ? (
          <span
            className="inline-block w-2 h-2 rounded-full bg-primary-500 shadow-glow-primary"
            title="Unread"
          />
        ) : (
          <span className="inline-block w-2 h-2 rounded-full bg-transparent" />
        )}
      </td>

      {/* Severity */}
      <td className="py-3.5 px-4 whitespace-nowrap">
        {renderSeverityBadge(notification.severity)}
      </td>

      {/* Title & Message Snippet */}
      <td className="py-3.5 px-4 max-w-md">
        <div className="flex flex-col gap-0.5">
          <span
            className={`text-sm ${
              !notification.is_read
                ? 'font-bold text-gray-900 dark:text-white'
                : 'font-medium text-gray-700 dark:text-gray-300'
            } truncate`}
          >
            {notification.title}
          </span>
          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
            {notification.message}
          </p>
        </div>
      </td>

      {/* Timestamp */}
      <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
        <div className="flex items-center gap-1">
          <Clock size={12} className="text-gray-400" />
          <span>{formatDate(notification.created_at)}</span>
        </div>
      </td>

      {/* Actions */}
      <td
        className="py-3.5 px-4 text-right whitespace-nowrap"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-end gap-1.5">
          {!notification.is_read && (
            <button
              type="button"
              disabled={isMarkingRead}
              onClick={() => onMarkRead(notification.notification_uuid)}
              className="p-1.5 rounded-lg text-primary-400 hover:text-primary-300 hover:bg-primary-500/10 transition-colors disabled:opacity-50"
              title="Mark as Read"
              aria-label="Mark notification as read"
            >
              {isMarkingRead ? (
                <Loader2 size={15} className="animate-spin" />
              ) : (
                <Check size={15} />
              )}
            </button>
          )}

          <button
            type="button"
            onClick={() => onSelect(notification)}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
            title="Inspect Notification"
            aria-label="Inspect notification"
          >
            <Eye size={15} />
          </button>
        </div>
      </td>
    </tr>
  )
}
