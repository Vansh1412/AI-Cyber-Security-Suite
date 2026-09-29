/**
 * frontend/src/components/soc/containment/PlaybookRunsTable.tsx
 * ────────────────────────────────────────────────────────────
 * Read-only audit log table for SOAR declarative playbook executions.
 * Displays execution provenance, fencing tokens, action counts, and completion statuses.
 */

import React from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Eye,
  Inbox,
  Loader2,
  RotateCcw,
} from 'lucide-react'
import type { PlaybookRunResponse } from '@/types/soc'

export interface PlaybookRunsTableProps {
  runs: PlaybookRunResponse[]
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  isLoading: boolean
  onSelectRun: (run: PlaybookRunResponse) => void
}

export function PlaybookRunsTable({
  runs,
  total,
  page,
  pageSize,
  onPageChange,
  isLoading,
  onSelectRun,
}: PlaybookRunsTableProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const startItem = total === 0 ? 0 : (page - 1) * pageSize + 1
  const endItem = Math.min(page * pageSize, total)

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

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 size={12} />
            Completed
          </span>
        )
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20 animate-pulse">
            <Loader2 size={12} className="animate-spin" />
            Running
          </span>
        )
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <AlertTriangle size={12} />
            Failed
          </span>
        )
      case 'REVERTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <RotateCcw size={12} />
            Reverted
          </span>
        )
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-500/10 text-gray-400">
            {status}
          </span>
        )
    }
  }

  return (
    <div className="bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm overflow-hidden flex flex-col">
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-light-border dark:border-dark-border bg-gray-50/60 dark:bg-dark-bg/60 text-2xs font-semibold text-gray-500 uppercase tracking-wider">
              <th className="py-3 px-4">Playbook Name & Run UUID</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Trigger Event</th>
              <th className="py-3 px-4">Steps Executed</th>
              <th className="py-3 px-4">Started At</th>
              <th className="py-3 px-4">Completed At</th>
              <th className="py-3 px-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-light-border dark:divide-dark-border">
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={`pb-skel-${i}`} className="animate-pulse">
                  <td className="py-4 px-4">
                    <div className="h-5 w-44 bg-gray-200 dark:bg-dark-border rounded mb-1" />
                    <div className="h-3 w-28 bg-gray-100 dark:bg-dark-border/50 rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-20 bg-gray-200 dark:bg-dark-border rounded-full" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-32 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-12 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-24 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-24 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4 text-right">
                    <div className="h-6 w-8 bg-gray-200 dark:bg-dark-border rounded ml-auto" />
                  </td>
                </tr>
              ))
            ) : runs.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-gray-500">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <div className="p-3 rounded-full bg-gray-100 dark:bg-dark-bg text-gray-400">
                      <Inbox size={24} />
                    </div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      No playbook runs recorded
                    </p>
                    <p className="text-xs text-gray-500 max-w-sm">
                      Automated threat containment playbooks trigger dynamically when qualifying alerts or repeated target compromise thresholds are met.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              runs.map((run) => (
                <tr
                  key={run.run_uuid}
                  className="border-b border-light-border dark:border-dark-border hover:bg-gray-50 dark:hover:bg-dark-hover/40 transition-colors cursor-pointer"
                  onClick={() => onSelectRun(run)}
                >
                  <td className="py-3.5 px-4">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-sm font-semibold text-gray-900 dark:text-white">
                        {run.playbook_name}
                      </span>
                      <span className="text-2xs font-mono text-gray-400">
                        {run.run_uuid}
                      </span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4">{renderStatusBadge(run.status)}</td>
                  <td className="py-3.5 px-4 text-xs font-mono text-gray-700 dark:text-gray-300">
                    {run.trigger_event}
                  </td>
                  <td className="py-3.5 px-4 text-xs text-gray-700 dark:text-gray-300">
                    <span className="font-semibold text-primary-400">{run.action_count}</span> actions
                  </td>
                  <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                    <div className="flex items-center gap-1">
                      <Clock size={12} className="text-gray-400" />
                      <span>{formatDate(run.started_at)}</span>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                    <span>{formatDate(run.completed_at)}</span>
                  </td>
                  <td
                    className="py-3.5 px-4 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      type="button"
                      onClick={() => onSelectRun(run)}
                      className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
                      title="Inspect Playbook Run"
                      aria-label="Inspect playbook run"
                    >
                      <Eye size={15} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-4 border-t border-light-border dark:border-dark-border flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-gray-500">
        <div>
          Showing <span className="font-semibold text-gray-900 dark:text-white">{startItem}</span> to{' '}
          <span className="font-semibold text-gray-900 dark:text-white">{endItem}</span> of{' '}
          <span className="font-semibold text-gray-900 dark:text-white">{total}</span> runs
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1 || isLoading}
            className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Previous Page"
            aria-label="Previous Page"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="px-2">
            Page {page} of {totalPages}
          </span>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages || isLoading}
            className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Next Page"
            aria-label="Next Page"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </div>
  )
}
