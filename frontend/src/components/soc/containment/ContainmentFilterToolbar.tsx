/**
 * frontend/src/components/soc/containment/ContainmentFilterToolbar.tsx
 * ──────────────────────────────────────────────────────────────────
 * Toolbar for filtering containment action records by type, status, and target identifier.
 * Provides the primary operator trigger for executing manual threat containment.
 */

import React from 'react'
import { Filter, Plus, RefreshCw, Search } from 'lucide-react'

export interface ContainmentFilterToolbarProps {
  searchQuery: string
  onSearchChange: (query: string) => void
  actionTypeFilter: string
  onActionTypeChange: (type: string) => void
  statusFilter: string
  onStatusChange: (status: string) => void
  onRefresh: () => void
  onOpenExecuteModal: () => void
  isRefreshing?: boolean
}

export function ContainmentFilterToolbar({
  searchQuery,
  onSearchChange,
  actionTypeFilter,
  onActionTypeChange,
  statusFilter,
  onStatusChange,
  onRefresh,
  onOpenExecuteModal,
  isRefreshing = false,
}: ContainmentFilterToolbarProps) {
  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm">
      {/* Search & Filters */}
      <div className="flex flex-wrap items-center gap-2.5 flex-1">
        {/* Search */}
        <div className="relative min-w-[220px] max-w-xs flex-1">
          <Search
            size={15}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"
          />
          <input
            type="text"
            placeholder="Search target identifier..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
          />
        </div>

        {/* Action Type Filter */}
        <div className="flex items-center gap-1.5 text-xs">
          <Filter size={13} className="text-gray-400 hidden sm:inline" />
          <select
            value={actionTypeFilter}
            onChange={(e) => onActionTypeChange(e.target.value)}
            aria-label="Filter by action type"
            className="px-2.5 py-1.5 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
          >
            <option value="">All Action Types</option>
            <option value="BLACKLIST_INDICATOR">Blacklist Indicator</option>
            <option value="QUARANTINE_TARGET">Quarantine Target</option>
            <option value="INVALIDATE_CACHE">Invalidate Cache</option>
            <option value="CREATE_INCIDENT">Create Incident</option>
            <option value="EMIT_SOC_EVENT">Emit SOC Event</option>
            <option value="SEND_NOTIFICATION">Send Notification</option>
          </select>
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5 text-xs">
          <select
            value={statusFilter}
            onChange={(e) => onStatusChange(e.target.value)}
            aria-label="Filter by status"
            className="px-2.5 py-1.5 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
          >
            <option value="">All Statuses</option>
            <option value="EXECUTED">Executed</option>
            <option value="BLOCKED_BY_ALLOWLIST">Blocked by Allowlist</option>
            <option value="REVERTED">Reverted</option>
            <option value="FAILED">Failed</option>
            <option value="PENDING">Pending</option>
            <option value="SKIPPED">Skipped</option>
          </select>
        </div>

        {/* Refresh */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-50"
          title="Refresh Actions"
          aria-label="Refresh containment actions"
        >
          <RefreshCw size={14} className={isRefreshing ? 'animate-spin' : ''} />
        </button>
      </div>

      {/* Primary Trigger: Execute Containment */}
      <button
        type="button"
        onClick={onOpenExecuteModal}
        className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-sm transition-all focus:outline-none focus:ring-2 focus:ring-rose-500/50"
      >
        <Plus size={14} />
        <span>Execute Containment Action</span>
      </button>
    </div>
  )
}
