/**
 * frontend/src/components/soc/incidents/IncidentTable.tsx
 * ────────────────────────────────────────────────────────
 * Paginated table container for Security Incidents.
 * Implements safe, honest cursorless pagination for flat array backend responses.
 */

import React from 'react'
import {
  AlertOctagon,
  ChevronLeft,
  ChevronRight,
  Inbox,
  Loader2,
} from 'lucide-react'
import type { Incident } from '@/types/soc'
import { IncidentRow } from './IncidentRow'

export interface IncidentTableProps {
  incidents: Incident[]
  isLoading: boolean
  page: number
  pageSize: number
  onPageChange: (newPage: number) => void
  onSelectIncident: (incident: Incident) => void
  onStatusClick: (incident: Incident) => void
  onAttachAlertClick: (incident: Incident) => void
  currentUserId?: number
}

export function IncidentTable({
  incidents,
  isLoading,
  page,
  pageSize,
  onPageChange,
  onSelectIncident,
  onStatusClick,
  onAttachAlertClick,
  currentUserId,
}: IncidentTableProps) {
  const isPreviousDisabled = page <= 1 || isLoading
  // Enabled only if the server returned a full page of records
  const isNextDisabled = incidents.length < pageSize || isLoading

  // Loading skeleton
  if (isLoading && incidents.length === 0) {
    return (
      <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-8 flex flex-col items-center justify-center min-h-[360px] space-y-3">
        <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
        <p className="text-xs text-gray-500">Loading security incidents...</p>
      </div>
    )
  }

  // End of records state (empty page > 1)
  if (!isLoading && incidents.length === 0 && page > 1) {
    return (
      <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-8 text-center space-y-4">
        <div className="w-12 h-12 rounded-full bg-amber-500/10 text-amber-400 mx-auto flex items-center justify-center">
          <AlertOctagon size={24} />
        </div>
        <div>
          <h3 className="text-sm font-bold text-gray-900 dark:text-white">
            End of incident records reached
          </h3>
          <p className="text-2xs text-gray-500 mt-1">
            There are no more incidents available on page {page}.
          </p>
        </div>
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-primary-600 hover:bg-primary-500 transition-colors"
        >
          <ChevronLeft size={14} />
          <span>Back to Page {page - 1}</span>
        </button>
      </div>
    )
  }

  // Empty state for page 1
  if (!isLoading && incidents.length === 0) {
    return (
      <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-12 text-center space-y-3">
        <div className="w-12 h-12 rounded-full bg-gray-500/10 text-gray-400 mx-auto flex items-center justify-center">
          <Inbox size={22} />
        </div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white">
          No security incidents found
        </h3>
        <p className="text-2xs text-gray-500 max-w-sm mx-auto">
          No incidents match the selected status or severity filters. Try adjusting your filter parameters or creating a new incident.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl shadow-xs overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse" aria-label="Security Incidents Table">
          <thead>
            <tr className="border-b border-light-border dark:border-dark-border/80 bg-light-hover/30 dark:bg-dark-surface/50 text-3xs font-bold uppercase tracking-wider text-gray-400">
              <th scope="col" className="py-3 px-4 w-28">Severity</th>
              <th scope="col" className="py-3 px-4">Title / Incident ID</th>
              <th scope="col" className="py-3 px-4 w-32">Status</th>
              <th scope="col" className="py-3 px-4 w-28">Linked Alerts</th>
              <th scope="col" className="py-3 px-4 w-36">Assignee</th>
              <th scope="col" className="py-3 px-4 w-36">Created</th>
              <th scope="col" className="py-3 px-4 w-24 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-light-border dark:divide-dark-border/40">
            {incidents.map((incident) => (
              <IncidentRow
                key={incident.id}
                incident={incident}
                onSelect={onSelectIncident}
                onStatusClick={onStatusClick}
                onAttachAlertClick={onAttachAlertClick}
                currentUserId={currentUserId}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination & Scope Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-light-border dark:border-dark-border/80 bg-light-card dark:bg-dark-card text-2xs text-gray-500">
        <div className="flex items-center gap-2">
          <span>
            Viewing Page <strong className="text-gray-700 dark:text-gray-300">{page}</strong>
          </span>
          <span>•</span>
          <span>
            <strong className="text-gray-700 dark:text-gray-300">{incidents.length}</strong> incidents loaded
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={isPreviousDisabled}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md border border-light-border dark:border-dark-border bg-white dark:bg-dark-surface text-gray-700 dark:text-gray-200 hover:bg-light-hover dark:hover:bg-dark-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-medium"
            aria-label="Previous Page"
          >
            <ChevronLeft size={13} />
            <span>Previous</span>
          </button>

          <span className="px-2 font-mono text-gray-400">Page {page}</span>

          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={isNextDisabled}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md border border-light-border dark:border-dark-border bg-white dark:bg-dark-surface text-gray-700 dark:text-gray-200 hover:bg-light-hover dark:hover:bg-dark-hover disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-medium"
            aria-label="Next Page"
          >
            <span>Next</span>
            <ChevronRight size={13} />
          </button>
        </div>
      </div>
    </div>
  )
}
