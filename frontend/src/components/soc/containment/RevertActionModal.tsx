/**
 * frontend/src/components/soc/containment/RevertActionModal.tsx
 * ─────────────────────────────────────────────────────────────
 * Destructive confirmation modal for safely reverting a previously executed
 * containment action (e.g. unblocking a blacklisted indicator or un-quarantining a target).
 */

import React, { useState } from 'react'
import { AlertTriangle, Loader2, RotateCcw, X } from 'lucide-react'
import type { ContainmentActionResponse } from '@/types/soc'

export interface RevertActionModalProps {
  isOpen: boolean
  action: ContainmentActionResponse | null
  onClose: () => void
  onConfirm: (actionUuid: string) => Promise<void>
  isPending: boolean
}

export function RevertActionModal({
  isOpen,
  action,
  onClose,
  onConfirm,
  isPending,
}: RevertActionModalProps) {
  const [error, setError] = useState<string | null>(null)

  if (!isOpen || !action) return null

  const handleConfirm = async () => {
    setError(null)
    try {
      await onConfirm(action.action_uuid)
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg || 'Failed to rollback containment action.')
    }
  }

  const getRevertDescription = () => {
    if (action.action_type === 'BLACKLIST_INDICATOR') {
      return `Deactivates the dynamic blacklist entry for '${action.target_identifier}', immediately restoring network traffic permissions.`
    }
    if (action.action_type === 'QUARANTINE_TARGET') {
      return `Restores monitoring target '${action.target_identifier}' to active polling status and clears quarantine error messages.`
    }
    return `Rolls back previously applied containment mutations owned by action ${action.action_uuid}.`
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className="w-full max-w-md bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border flex items-center justify-between bg-purple-500/5">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <RotateCcw size={18} />
            </div>
            <div>
              <h2 className="text-base font-bold text-gray-900 dark:text-white">
                Revert Containment Action
              </h2>
              <p className="text-xs text-gray-500">
                Confirm provenance-safe operational rollback
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={isPending}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors disabled:opacity-50"
            aria-label="Close modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400">
              {error}
            </div>
          )}

          <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-dark-bg/60 border border-light-border dark:border-dark-border space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Action Type</span>
              <span className="font-semibold text-gray-900 dark:text-white font-mono">
                {action.action_type}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Target</span>
              <span className="font-semibold text-gray-900 dark:text-white font-mono truncate max-w-[200px]">
                {action.target_identifier}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Action UUID</span>
              <span className="font-mono text-2xs text-gray-500">
                {action.action_uuid}
              </span>
            </div>
          </div>

          {/* Operational Impact Warning */}
          <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 space-y-1">
            <div className="flex items-center gap-1.5 font-semibold text-amber-400">
              <AlertTriangle size={14} />
              <span>Operational Consequence</span>
            </div>
            <p className="text-2xs text-amber-200/90 leading-relaxed">
              {getRevertDescription()}
            </p>
          </div>

          <p className="text-xs text-gray-500">
            This operation is logged to the system audit trail and broadcasts a real-time reversion frame to connected SOC consoles.
          </p>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-light-border dark:border-dark-border bg-gray-50/50 dark:bg-dark-bg/50 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            disabled={isPending}
            className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-lg transition-colors disabled:opacity-50"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={handleConfirm}
            disabled={isPending}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow-sm transition-all disabled:opacity-50"
          >
            {isPending && <Loader2 size={14} className="animate-spin" />}
            <span>Confirm Rollback</span>
          </button>
        </div>
      </div>
    </div>
  )
}
