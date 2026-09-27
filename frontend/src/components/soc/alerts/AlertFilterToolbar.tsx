/**
 * frontend/src/components/soc/alerts/AlertFilterToolbar.tsx
 * ─────────────────────────────────────────────────────────
 * Filter toolbar with status tabs, severity dropdown, debounced search, and reset.
 */

import React, { useEffect, useState } from 'react'
import { RefreshCcw, Search, X } from 'lucide-react'
import type { AlertStatus, EventSeverity } from '@/types/soc'
import { clsx } from 'clsx'

export interface AlertFilterState {
  status?: AlertStatus | string
  severity?: EventSeverity | string
  indicator_type?: string
  search?: string
  rule_name?: string
}

export interface AlertFilterToolbarProps {
  filters: AlertFilterState
  onFilterChange: (newFilters: Partial<AlertFilterState>) => void
  onResetFilters: () => void
  isFiltered: boolean
  totalItems?: number
}

const STATUS_TABS: Array<{ label: string; value: string }> = [
  { label: 'All Alerts', value: '' },
  { label: 'Open', value: 'OPEN' },
  { label: 'Claimed', value: 'ACKNOWLEDGED' },
  { label: 'Resolved', value: 'RESOLVED' },
  { label: 'Dismissed', value: 'DISMISSED' },
]

const SEVERITIES: Array<{ label: string; value: string }> = [
  { label: 'All Severities', value: '' },
  { label: 'Critical', value: 'CRITICAL' },
  { label: 'High', value: 'HIGH' },
  { label: 'Medium', value: 'MEDIUM' },
  { label: 'Low', value: 'LOW' },
  { label: 'Info', value: 'INFO' },
]

const INDICATOR_TYPES: Array<{ label: string; value: string }> = [
  { label: 'All Indicators', value: '' },
  { label: 'Domain', value: 'DOMAIN' },
  { label: 'URL', value: 'URL' },
  { label: 'IP Address', value: 'IP' },
  { label: 'File Hash', value: 'HASH' },
]

export function AlertFilterToolbar({
  filters,
  onFilterChange,
  onResetFilters,
  isFiltered,
  totalItems,
}: AlertFilterToolbarProps) {
  // Local state for debounced search input
  const [searchInput, setSearchInput] = useState(filters.search || filters.rule_name || '')

  useEffect(() => {
    setSearchInput(filters.search || filters.rule_name || '')
  }, [filters.search, filters.rule_name])

  // 300ms debounce for search query
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchInput !== (filters.search || '')) {
        onFilterChange({ search: searchInput.trim() || undefined })
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [searchInput, filters.search, onFilterChange])

  return (
    <div className="glass-card p-4 space-y-3.5">
      {/* Top row: Status Tabs & Total Count */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-dark-border pb-3">
        <div className="flex items-center gap-1.5 overflow-x-auto py-0.5">
          {STATUS_TABS.map((tab) => {
            const isActive = (filters.status || '') === tab.value
            return (
              <button
                key={tab.value}
                type="button"
                onClick={() => onFilterChange({ status: tab.value || undefined })}
                className={clsx(
                  'px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all whitespace-nowrap',
                  isActive
                    ? 'bg-primary-600 text-white shadow-glow-primary'
                    : 'text-gray-400 hover:text-white hover:bg-dark-hover bg-dark-surface/50'
                )}
              >
                {tab.label}
              </button>
            )
          })}
        </div>

        {totalItems !== undefined && (
          <span className="text-xs text-gray-400 font-mono">
            {totalItems.toLocaleString()} matching {totalItems === 1 ? 'alert' : 'alerts'}
          </span>
        )}
      </div>

      {/* Bottom row: Severity, Indicator Type, Text Search, Reset */}
      <div className="flex flex-wrap items-center gap-2.5">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[220px]">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none"
          />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search indicator, rule, title..."
            className="w-full pl-8 pr-8 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-white placeholder-gray-500 focus:outline-none focus:border-primary-500 transition-colors"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => {
                setSearchInput('')
                onFilterChange({ search: undefined, rule_name: undefined })
              }}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white p-0.5"
            >
              <X size={13} />
            </button>
          )}
        </div>

        {/* Severity Selector */}
        <div className="w-36">
          <select
            value={filters.severity || ''}
            onChange={(e) => onFilterChange({ severity: e.target.value || undefined })}
            className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-gray-300 focus:outline-none focus:border-primary-500 transition-colors cursor-pointer"
          >
            {SEVERITIES.map((sev) => (
              <option key={sev.value} value={sev.value} className="bg-dark-surface text-white">
                {sev.label}
              </option>
            ))}
          </select>
        </div>

        {/* Indicator Type Selector */}
        <div className="w-36">
          <select
            value={filters.indicator_type || ''}
            onChange={(e) => onFilterChange({ indicator_type: e.target.value || undefined })}
            className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-gray-300 focus:outline-none focus:border-primary-500 transition-colors cursor-pointer"
          >
            {INDICATOR_TYPES.map((type) => (
              <option key={type.value} value={type.value} className="bg-dark-surface text-white">
                {type.label}
              </option>
            ))}
          </select>
        </div>

        {/* Reset Filters Action */}
        {isFiltered && (
          <button
            type="button"
            onClick={onResetFilters}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium text-gray-400 hover:text-white hover:bg-dark-hover border border-dark-border transition-colors shrink-0"
            title="Clear all active filters"
          >
            <RefreshCcw size={12} />
            <span>Reset</span>
          </button>
        )}
      </div>
    </div>
  )
}
