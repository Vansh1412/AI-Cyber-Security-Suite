/**
 * frontend/src/components/soc/incidents/IncidentFilterToolbar.tsx
 * ────────────────────────────────────────────────────────────────
 * Filter controls for Security Incidents Management.
 * Filters: Status, Severity (backed strictly by backend database query filters).
 * Note: Freeform search is omitted per Phase 6C architecture specifications.
 */

import React from 'react'
import { Filter, Plus, RotateCcw } from 'lucide-react'
import type { EventSeverity, IncidentStatus } from '@/types/soc'

export interface IncidentFilterState {
  status?: IncidentStatus | string
  severity?: EventSeverity | string
}

export interface IncidentFilterToolbarProps {
  filters: IncidentFilterState
  onFilterChange: (filters: Partial<IncidentFilterState>) => void
  onReset: () => void
  onCreateClick: () => void
  isFiltered: boolean
}

const STATUS_OPTIONS: { value: IncidentStatus | ''; label: string }[] = [
  { value: '', label: 'All Statuses' },
  { value: 'OPEN', label: 'Open' },
  { value: 'INVESTIGATING', label: 'Investigating' },
  { value: 'CONTAINED', label: 'Contained' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'CLOSED', label: 'Closed' },
]

const SEVERITY_OPTIONS: { value: EventSeverity | ''; label: string }[] = [
  { value: '', label: 'All Severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
  { value: 'INFO', label: 'Info' },
]

export function IncidentFilterToolbar({
  filters,
  onFilterChange,
  onReset,
  onCreateClick,
  isFiltered,
}: IncidentFilterToolbarProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-3.5 shadow-xs">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          <Filter size={14} className="text-primary-400" />
          <span>Filters:</span>
        </div>

        {/* Status Filter */}
        <select
          value={filters.status || ''}
          onChange={(e) => onFilterChange({ status: e.target.value || undefined })}
          aria-label="Filter by Incident Status"
          className="bg-white border border-light-border text-gray-800 text-xs rounded-lg px-2.5 py-1.5 focus:outline-hidden focus:border-primary-500 transition-colors dark:bg-dark-surface dark:border-dark-border dark:text-gray-200"
        >
          {STATUS_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>

        {/* Severity Filter */}
        <select
          value={filters.severity || ''}
          onChange={(e) => onFilterChange({ severity: e.target.value || undefined })}
          aria-label="Filter by Incident Severity"
          className="bg-white border border-light-border text-gray-800 text-xs rounded-lg px-2.5 py-1.5 focus:outline-hidden focus:border-primary-500 transition-colors dark:bg-dark-surface dark:border-dark-border dark:text-gray-200"
        >
          {SEVERITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>

        {/* Reset Filter Button */}
        {isFiltered && (
          <button
            type="button"
            onClick={onReset}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white px-2 py-1 rounded-md hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
            title="Reset all filters"
          >
            <RotateCcw size={13} />
            <span>Reset</span>
          </button>
        )}
      </div>

      {/* Primary Action: Create Incident */}
      <button
        type="button"
        onClick={onCreateClick}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-primary-600 hover:bg-primary-500 transition-colors shadow-xs"
      >
        <Plus size={15} />
        <span>New Incident</span>
      </button>
    </div>
  )
}
