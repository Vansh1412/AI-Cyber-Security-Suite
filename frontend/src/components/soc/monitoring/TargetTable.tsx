/**
 * frontend/src/components/soc/monitoring/TargetTable.tsx
 * ───────────────────────────────────────────────────────
 * Paginated table container for Monitored Targets Fleet.
 * Uses total, page, page_size, and has_more from backend MonitoringTargetListResponse.
 */

import React from 'react'
import {
  ChevronLeft,
  ChevronRight,
  Loader2,
  Radio,
} from 'lucide-react'
import type { MonitoringTarget } from '@/types/soc'
import { TargetRow } from './TargetRow'

export interface TargetTableProps {
  targets: MonitoringTarget[]
  total: number
  page: number
  pageSize: number
  hasMore: boolean
  isLoading: boolean
  onPageChange: (newPage: number) => void
  onSelectTarget: (target: MonitoringTarget) => void
  onCheckNow: (target: MonitoringTarget) => void
  onTogglePauseResume: (target: MonitoringTarget) => void
  onReactivate: (target: MonitoringTarget) => void
  onDelete: (target: MonitoringTarget) => void
  checkingTargetUuid?: string | null
}

export function TargetTable({
  targets,
  total,
  page,
  pageSize,
  hasMore,
  isLoading,
  onPageChange,
  onSelectTarget,
  onCheckNow,
  onTogglePauseResume,
  onReactivate,
  onDelete,
  checkingTargetUuid,
}: TargetTableProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const isPreviousDisabled = page <= 1 || isLoading
  const isNextDisabled = !hasMore || page >= totalPages || isLoading

  // Loading skeleton
  if (isLoading && targets.length === 0) {
    return (
      <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-8 flex flex-col items-center justify-center min-h-[360px] space-y-3">
        <Loader2 className="w-8 h-8 text-primary-500 animate-spin" />
        <p className="text-xs text-gray-500">Loading monitored target fleet...</p>
      </div>
    )
  }

  // Empty state
  if (!isLoading && targets.length === 0) {
    return (
      <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl p-12 text-center space-y-3">
        <div className="w-12 h-12 rounded-full bg-gray-500/10 text-gray-400 mx-auto flex items-center justify-center">
          <Radio size={22} />
        </div>
        <h3 className="text-sm font-bold text-gray-900 dark:text-white">
          No monitored targets found
        </h3>
        <p className="text-2xs text-gray-500 max-w-sm mx-auto">
          No targets currently match your filter. Register a new target to initiate continuous automated probe monitoring.
        </p>
      </div>
    )
  }

  return (
    <div className="bg-light-card border border-light-border dark:bg-dark-card dark:border-dark-border rounded-xl shadow-xs overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse" aria-label="Monitored Targets Fleet Table">
          <thead>
            <tr className="border-b border-light-border dark:border-dark-border/80 bg-light-hover/30 dark:bg-dark-surface/50 text-3xs font-bold uppercase tracking-wider text-gray-400">
              <th scope="col" className="py-3 px-4 w-32">Status</th>
              <th scope="col" className="py-3 px-4">Target Host / URL</th>
              <th scope="col" className="py-3 px-4 w-32">Interval</th>
              <th scope="col" className="py-3 px-4 w-44">Last Execution</th>
              <th scope="col" className="py-3 px-4 w-40">Next Execution</th>
              <th scope="col" className="py-3 px-4 w-36 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-light-border dark:divide-dark-border/40">
            {targets.map((target) => (
              <TargetRow
                key={target.target_uuid}
                target={target}
                onSelect={onSelectTarget}
                onCheckNow={onCheckNow}
                onTogglePauseResume={onTogglePauseResume}
                onReactivate={onReactivate}
                onDelete={onDelete}
                isCheckingNow={checkingTargetUuid === target.target_uuid}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-light-border dark:border-dark-border/80 bg-light-card dark:bg-dark-card text-2xs text-gray-500">
        <div>
          <span>
            Showing <strong className="text-gray-700 dark:text-gray-300">{targets.length}</strong> of{' '}
            <strong className="text-gray-700 dark:text-gray-300">{total}</strong> total targets
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

          <span className="px-2 font-mono text-gray-400">
            Page {page} of {totalPages}
          </span>

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
