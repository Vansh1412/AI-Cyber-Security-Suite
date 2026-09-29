/**
 * frontend/src/components/soc/containment/ContainmentActionTable.tsx
 * ────────────────────────────────────────────────────────────────
 * Data table displaying containment actions with server-side pagination,
 * loading skeletons, empty states, and action triggers.
 */

import React from 'react'
import { ChevronLeft, ChevronRight, Inbox } from 'lucide-react'
import type { ContainmentActionResponse } from '@/types/soc'
import { ContainmentActionRow } from './ContainmentActionRow'

export interface ContainmentActionTableProps {
  actions: ContainmentActionResponse[]
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  isLoading: boolean
  onSelectAction: (action: ContainmentActionResponse) => void
  onRevertAction: (action: ContainmentActionResponse) => void
  revertingActionUuid?: string | null
}

export function ContainmentActionTable({
  actions,
  total,
  page,
  pageSize,
  onPageChange,
  isLoading,
  onSelectAction,
  onRevertAction,
  revertingActionUuid,
}: ContainmentActionTableProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const startItem = total === 0 ? 0 : (page - 1) * pageSize + 1
  const endItem = Math.min(page * pageSize, total)

  return (
    <div className="bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm overflow-hidden flex flex-col">
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-light-border dark:border-dark-border bg-gray-50/60 dark:bg-dark-bg/60 text-2xs font-semibold text-gray-500 uppercase tracking-wider">
              <th className="py-3 px-4">Action Type & ID</th>
              <th className="py-3 px-4">Target Identifier</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Trigger & Provenance</th>
              <th className="py-3 px-4">Created</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-light-border dark:divide-dark-border">
            {isLoading ? (
              // Loading skeletons
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={`skeleton-${i}`} className="animate-pulse">
                  <td className="py-4 px-4">
                    <div className="h-5 w-24 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-48 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-20 bg-gray-200 dark:bg-dark-border rounded-full" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-32 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4">
                    <div className="h-4 w-24 bg-gray-200 dark:bg-dark-border rounded" />
                  </td>
                  <td className="py-4 px-4 text-right">
                    <div className="h-6 w-16 bg-gray-200 dark:bg-dark-border rounded ml-auto" />
                  </td>
                </tr>
              ))
            ) : actions.length === 0 ? (
              // Empty state
              <tr>
                <td colSpan={6} className="py-12 text-center text-gray-500">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <div className="p-3 rounded-full bg-gray-100 dark:bg-dark-bg text-gray-400">
                      <Inbox size={24} />
                    </div>
                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                      No containment actions found
                    </p>
                    <p className="text-xs text-gray-500 max-w-sm">
                      No containment actions match the current filter criteria, or none have been executed yet.
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              actions.map((action) => (
                <ContainmentActionRow
                  key={action.action_uuid}
                  action={action}
                  onSelect={onSelectAction}
                  onRevert={onRevertAction}
                  isReverting={revertingActionUuid === action.action_uuid}
                />
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
          <span className="font-semibold text-gray-900 dark:text-white">{total}</span> actions
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
