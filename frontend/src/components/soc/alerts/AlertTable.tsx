/**
 * frontend/src/components/soc/alerts/AlertTable.tsx
 * ─────────────────────────────────────────────────
 * Main tabular list displaying paginated security alerts with sorting indicator and empty/loading states.
 */

import React from 'react'
import { ChevronLeft, ChevronRight, ShieldCheck } from 'lucide-react'
import type { Alert } from '@/types/soc'
import { AlertRow } from './AlertRow'

export interface AlertTableProps {
  alerts: Alert[]
  total: number
  page: number
  pageSize: number
  isLoading: boolean
  selectedAlertUuid?: string | null
  onPageChange: (newPage: number) => void
  onPageSizeChange: (newPageSize: number) => void
  onSelectAlert: (alert: Alert) => void
  onAcknowledge: (alert: Alert) => void
  onResolve: (alert: Alert) => void
  onDismiss: (alert: Alert) => void
  onReopen: (alert: Alert) => void
  onEscalate: (alert: Alert) => void
  onResetFilters?: () => void
  isAdmin?: boolean
}

export function AlertTable({
  alerts,
  total,
  page,
  pageSize,
  isLoading,
  selectedAlertUuid,
  onPageChange,
  onPageSizeChange,
  onSelectAlert,
  onAcknowledge,
  onResolve,
  onDismiss,
  onReopen,
  onEscalate,
  onResetFilters,
  isAdmin = false,
}: AlertTableProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const startIdx = total === 0 ? 0 : (page - 1) * pageSize + 1
  const endIdx = Math.min(total, page * pageSize)

  return (
    <div className="glass-card overflow-hidden">
      {/* Table Scroll Container */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-dark-border text-2xs font-semibold text-gray-400 uppercase tracking-wider bg-dark-surface/40 select-none">
              <th className="px-3.5 py-3 w-28">Severity</th>
              <th className="px-3 py-3 w-28">Status</th>
              <th className="px-3 py-3">Detection Rule & Title</th>
              <th className="px-3 py-3">Threat Indicator</th>
              <th className="px-3 py-3 text-center w-24">Events</th>
              <th className="px-3 py-3 w-32">
                <span className="inline-flex items-center gap-1 text-primary-400" title="Ordered by most recent event (server-side)">
                  Last Seen <span className="font-mono">↓</span>
                </span>
              </th>
              <th className="px-3.5 py-3 text-right w-44">Triage Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              // Loading Skeleton Rows
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-dark-border/40 animate-pulse">
                  <td className="px-3.5 py-3.5">
                    <div className="h-5 w-16 bg-white/5 rounded-full" />
                  </td>
                  <td className="px-3 py-3.5">
                    <div className="h-5 w-16 bg-white/5 rounded-full" />
                  </td>
                  <td className="px-3 py-3.5">
                    <div className="h-4 w-48 bg-white/5 rounded mb-1.5" />
                    <div className="h-3 w-32 bg-white/5 rounded" />
                  </td>
                  <td className="px-3 py-3.5">
                    <div className="h-4 w-36 bg-white/5 rounded" />
                  </td>
                  <td className="px-3 py-3.5 text-center">
                    <div className="h-4 w-8 bg-white/5 rounded mx-auto" />
                  </td>
                  <td className="px-3 py-3.5">
                    <div className="h-4 w-20 bg-white/5 rounded" />
                  </td>
                  <td className="px-3.5 py-3.5 text-right">
                    <div className="h-6 w-28 bg-white/5 rounded ml-auto" />
                  </td>
                </tr>
              ))
            ) : alerts.length === 0 ? (
              // Empty State
              <tr>
                <td colSpan={7} className="py-14 text-center">
                  <div className="max-w-sm mx-auto flex flex-col items-center">
                    <div className="w-12 h-12 rounded-2xl bg-primary-500/10 border border-primary-500/20 flex items-center justify-center text-primary-400 mb-3">
                      <ShieldCheck size={24} />
                    </div>
                    <p className="text-base font-semibold text-white">No alerts detected</p>
                    <p className="text-xs text-gray-500 mt-1 max-w-xs">
                      No security alerts match the selected filter criteria or the triage queue is currently clear.
                    </p>
                    {onResetFilters && (
                      <button
                        type="button"
                        onClick={onResetFilters}
                        className="mt-4 px-4 py-2 bg-dark-hover hover:bg-dark-border text-gray-200 rounded-xl text-xs font-medium border border-dark-border transition-colors"
                      >
                        Reset Filter Criteria
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ) : (
              // Alert Rows
              alerts.map((alert) => (
                <AlertRow
                  key={alert.alert_uuid}
                  alert={alert}
                  isSelected={selectedAlertUuid === alert.alert_uuid}
                  onSelect={onSelectAlert}
                  onAcknowledge={onAcknowledge}
                  onResolve={onResolve}
                  onDismiss={onDismiss}
                  onReopen={onReopen}
                  onEscalate={onEscalate}
                  isAdmin={isAdmin}
                />
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-dark-border bg-dark-surface/20 text-xs">
        <div className="flex items-center gap-2 text-gray-400">
          <span>
            Showing <strong className="text-white">{startIdx}</strong>–<strong className="text-white">{endIdx}</strong> of{' '}
            <strong className="text-white">{total.toLocaleString()}</strong> alerts
          </span>
          <span className="text-gray-600">|</span>
          <div className="flex items-center gap-1.5">
            <span className="text-2xs text-gray-500">Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="bg-dark-surface border border-dark-border rounded px-2 py-0.5 text-xs text-gray-300 focus:outline-none focus:border-primary-500 cursor-pointer"
            >
              <option value={20}>20</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            disabled={page <= 1 || isLoading}
            onClick={() => onPageChange(page - 1)}
            className="p-1.5 rounded-lg border border-dark-border text-gray-400 hover:text-white hover:bg-dark-hover disabled:opacity-40 disabled:pointer-events-none transition-colors"
            title="Previous page"
          >
            <ChevronLeft size={14} />
          </button>

          <span className="px-2 text-xs font-mono text-gray-400">
            Page <strong className="text-white">{page}</strong> of <strong className="text-white">{totalPages}</strong>
          </span>

          <button
            type="button"
            disabled={page >= totalPages || isLoading}
            onClick={() => onPageChange(page + 1)}
            className="p-1.5 rounded-lg border border-dark-border text-gray-400 hover:text-white hover:bg-dark-hover disabled:opacity-40 disabled:pointer-events-none transition-colors"
            title="Next page"
          >
            <ChevronRight size={14} />
          </button>
        </div>
      </div>
    </div>
  )
}
