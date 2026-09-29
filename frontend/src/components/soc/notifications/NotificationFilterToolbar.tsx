/**
 * frontend/src/components/soc/notifications/NotificationFilterToolbar.tsx
 * ──────────────────────────────────────────────────────────────────────
 * Filter controls for the notifications inbox: read/unread pills, severity filter,
 * refresh button, and "Mark All as Read" trigger.
 */

import React from 'react'
import { CheckCheck, Filter, Loader2, RefreshCw } from 'lucide-react'

export interface NotificationFilterToolbarProps {
  readFilter: 'ALL' | 'UNREAD' | 'READ'
  onReadFilterChange: (filter: 'ALL' | 'UNREAD' | 'READ') => void
  severityFilter: string
  onSeverityFilterChange: (sev: string) => void
  onMarkAllRead: () => void
  isMarkingAllRead: boolean
  unreadCount: number
  onRefresh: () => void
  isRefreshing?: boolean
}

export function NotificationFilterToolbar({
  readFilter,
  onReadFilterChange,
  severityFilter,
  onSeverityFilterChange,
  onMarkAllRead,
  isMarkingAllRead,
  unreadCount,
  onRefresh,
  isRefreshing = false,
}: NotificationFilterToolbarProps) {
  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm">
      {/* Read Status Filter & Severity */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Read / Unread Pills */}
        <div className="flex items-center gap-1 bg-gray-100 dark:bg-dark-bg p-1 rounded-lg border border-light-border dark:border-dark-border text-xs font-medium">
          <button
            type="button"
            onClick={() => onReadFilterChange('ALL')}
            className={`px-3 py-1 rounded-md transition-all ${
              readFilter === 'ALL'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs font-semibold'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            All
          </button>
          <button
            type="button"
            onClick={() => onReadFilterChange('UNREAD')}
            className={`px-3 py-1 rounded-md transition-all flex items-center gap-1.5 ${
              readFilter === 'UNREAD'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs font-semibold'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <span>Unread</span>
            {unreadCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-2xs font-bold bg-primary-500 text-white">
                {unreadCount}
              </span>
            )}
          </button>
          <button
            type="button"
            onClick={() => onReadFilterChange('READ')}
            className={`px-3 py-1 rounded-md transition-all ${
              readFilter === 'READ'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs font-semibold'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Read
          </button>
        </div>

        {/* Severity Selector */}
        <div className="flex items-center gap-1.5 text-xs">
          <Filter size={13} className="text-gray-400 hidden sm:inline" />
          <select
            value={severityFilter}
            onChange={(e) => onSeverityFilterChange(e.target.value)}
            aria-label="Filter by severity"
            className="px-2.5 py-1.5 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {/* Refresh */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-50"
          title="Refresh Notifications"
          aria-label="Refresh notifications"
        >
          <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Mark All as Read */}
      <button
        type="button"
        disabled={isMarkingAllRead || unreadCount === 0}
        onClick={onMarkAllRead}
        className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-100 hover:bg-gray-200 dark:bg-dark-bg dark:hover:bg-dark-hover border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {isMarkingAllRead ? (
          <Loader2 size={14} className="animate-spin text-primary-500" />
        ) : (
          <CheckCheck size={14} className="text-primary-400" />
        )}
        <span>Mark All as Read</span>
      </button>
    </div>
  )
}
