/**
 * frontend/src/components/soc/monitoring/TargetFilterToolbar.tsx
 * ───────────────────────────────────────────────────────────────
 * Filter toolbar for Continuous Target Monitoring.
 * Supports activation state filtering (active-only vs include-inactive) and target creation.
 * Note: Freeform domain search is omitted per Phase 6C architecture specifications.
 */

import React from 'react'
import { Filter, Plus, RefreshCw } from 'lucide-react'

export interface TargetFilterToolbarProps {
  includeInactive: boolean
  onToggleIncludeInactive: (val: boolean) => void
  onRefresh: () => void
  onAddTargetClick: () => void
  isRefreshing: boolean
}

export function TargetFilterToolbar({
  includeInactive,
  onToggleIncludeInactive,
  onRefresh,
  onAddTargetClick,
  isRefreshing,
}: TargetFilterToolbarProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-3.5 shadow-2xs">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          <Filter size={14} className="text-primary-400" />
          <span>Fleet Filter:</span>
        </div>

        {/* Active vs Inactive Dropdown */}
        <select
          value={includeInactive ? 'all' : 'active'}
          onChange={(e) => onToggleIncludeInactive(e.target.value === 'all')}
          aria-label="Filter target activation status"
          className="bg-white border border-light-border text-gray-800 text-xs rounded-lg px-2.5 py-1.5 focus:outline-hidden focus:border-primary-500 transition-colors dark:bg-dark-surface dark:border-dark-border dark:text-gray-200"
        >
          <option value="active">Active Probes Only</option>
          <option value="all">All Targets (Include Paused / Deactivated)</option>
        </select>

        {/* Manual Refresh */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white px-2.5 py-1.5 rounded-lg border border-light-border dark:border-dark-border hover:bg-light-hover dark:hover:bg-dark-hover disabled:opacity-50 transition-colors"
          title="Refresh target fleet data"
        >
          <RefreshCw size={13} className={isRefreshing ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Primary Action: Register Target */}
      <button
        type="button"
        onClick={onAddTargetClick}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-primary-600 hover:bg-primary-500 transition-colors shadow-2xs"
      >
        <Plus size={15} />
        <span>Add Monitored Target</span>
      </button>
    </div>
  )
}
