/**
 * frontend/src/components/soc/notifications/NotificationDetailDrawer.tsx
 * ─────────────────────────────────────────────────────────────────────
 * Detail drawer displaying the full notification text, creation metadata,
 * safe external link button with URL scheme sanitization, and read toggle.
 */

import React from 'react'
import {
  Check,
  ExternalLink,
  Loader2,
  X,
} from 'lucide-react'
import type { NotificationItem } from '@/types/soc'

export interface NotificationDetailDrawerProps {
  notification: NotificationItem | null
  isOpen: boolean
  onClose: () => void
  onMarkRead: (uuid: string) => void
  isMarkingRead?: boolean
}

export function NotificationDetailDrawer({
  notification,
  isOpen,
  onClose,
  onMarkRead,
  isMarkingRead = false,
}: NotificationDetailDrawerProps) {
  if (!isOpen || !notification) return null

  const formatTimestamp = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      return new Date(dateStr).toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium',
      })
    } catch {
      return dateStr
    }
  }

  // Security gate SG-S6D-07: Sanitize link_url against javascript: and malicious protocols
  const isSafeUrl = (url?: string | null): boolean => {
    if (!url) return false
    const trimmed = url.trim().toLowerCase()
    return (
      trimmed.startsWith('https://') ||
      trimmed.startsWith('http://') ||
      trimmed.startsWith('/')
    )
  }

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
      <div
        className="w-full max-w-lg bg-white dark:bg-dark-surface border-l border-light-border dark:border-dark-border h-full flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border flex items-start justify-between gap-4 bg-gray-50/50 dark:bg-dark-bg/50">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-2xs font-bold px-2 py-0.5 rounded uppercase tracking-wider bg-primary-500/10 text-primary-400 border border-primary-500/20">
                {notification.severity}
              </span>
              <span className="text-2xs font-mono text-gray-500">
                {notification.is_read ? 'Read' : 'Unread'}
              </span>
            </div>
            <h2 className="text-lg font-bold text-gray-900 dark:text-white">
              {notification.title}
            </h2>
            <p className="text-2xs font-mono text-gray-400 mt-1">
              UUID: {notification.notification_uuid}
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
            title="Close Drawer"
            aria-label="Close notification drawer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-3 text-xs bg-gray-50 dark:bg-dark-bg/40 p-4 rounded-xl border border-light-border dark:border-dark-border">
            <div>
              <span className="text-gray-400 block text-2xs">Received At</span>
              <span className="text-gray-700 dark:text-gray-300">
                {formatTimestamp(notification.created_at)}
              </span>
            </div>
            <div>
              <span className="text-gray-400 block text-2xs">Notification ID</span>
              <span className="text-gray-700 dark:text-gray-300 font-mono">
                #{notification.id}
              </span>
            </div>
          </div>

          {/* Full Message Text */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Notification Details
            </h3>
            <div className="p-4 rounded-xl bg-gray-50 dark:bg-dark-bg/60 border border-light-border dark:border-dark-border text-xs text-gray-800 dark:text-gray-200 leading-relaxed whitespace-pre-wrap">
              {notification.message}
            </div>
          </div>

          {/* Safe Action Link */}
          {notification.link_url && isSafeUrl(notification.link_url) && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                Related Resource Link
              </h3>
              <a
                href={notification.link_url}
                target={notification.link_url.startsWith('/') ? undefined : '_blank'}
                rel={notification.link_url.startsWith('/') ? undefined : 'noopener noreferrer'}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-primary-500/10 text-primary-400 hover:bg-primary-500/20 border border-primary-500/20 transition-all"
              >
                <span>Navigate to Resource</span>
                <ExternalLink size={13} />
              </a>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-light-border dark:border-dark-border bg-gray-50/50 dark:bg-dark-bg/50 flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-lg transition-colors"
          >
            Close
          </button>

          {!notification.is_read && (
            <button
              type="button"
              disabled={isMarkingRead}
              onClick={() => onMarkRead(notification.notification_uuid)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-primary-600 hover:bg-primary-500 text-white shadow-sm transition-all disabled:opacity-50"
            >
              {isMarkingRead ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <Check size={14} />
              )}
              <span>Mark as Read</span>
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
