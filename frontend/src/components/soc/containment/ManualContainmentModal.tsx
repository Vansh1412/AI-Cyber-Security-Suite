/**
 * frontend/src/components/soc/containment/ManualContainmentModal.tsx
 * ─────────────────────────────────────────────────────────────────
 * Explicit two-step modal for manually invoking typed SOAR containment actions.
 * Enforces pessimistic execution and highlights destructive operational impacts.
 */

import React, { useState } from 'react'
import {
  AlertTriangle,
  Loader2,
  ShieldAlert,
  X,
} from 'lucide-react'
import type { ContainmentActionType, ContainmentRequest } from '@/types/soc'

export interface ManualContainmentModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (payload: ContainmentRequest) => Promise<void>
  isPending: boolean
}

export function ManualContainmentModal({
  isOpen,
  onClose,
  onSubmit,
  isPending,
}: ManualContainmentModalProps) {
  const [actionType, setActionType] = useState<ContainmentActionType>('BLACKLIST_INDICATOR')
  const [targetIdentifier, setTargetIdentifier] = useState('')
  const [alertId, setAlertId] = useState<string>('')
  const [reason, setReason] = useState('Analyst manual containment')
  const [error, setError] = useState<string | null>(null)

  if (!isOpen) return null

  const isDestructive =
    actionType === 'BLACKLIST_INDICATOR' || actionType === 'QUARANTINE_TARGET'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    const trimmedTarget = targetIdentifier.trim()
    if (!trimmedTarget) {
      setError('Target identifier is required.')
      return
    }

    const payload: ContainmentRequest = {
      action_type: actionType,
      target_identifier: trimmedTarget,
      alert_id: alertId ? parseInt(alertId, 10) : undefined,
      reason: reason.trim() || 'Analyst manual containment',
    }

    try {
      await onSubmit(payload)
      setTargetIdentifier('')
      setAlertId('')
      setReason('Analyst manual containment')
      onClose()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg || 'Failed to invoke containment action.')
    }
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className="w-full max-w-lg bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border flex items-center justify-between bg-gray-50/50 dark:bg-dark-bg/50">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert size={18} />
            </div>
            <div>
              <h2 className="text-base font-bold text-gray-900 dark:text-white">
                Execute Containment Action
              </h2>
              <p className="text-xs text-gray-500">
                Invoke a typed SOAR mitigation against a threat target
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

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400">
              {error}
            </div>
          )}

          {/* Action Type Selection */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Action Type <span className="text-rose-500">*</span>
            </label>
            <select
              value={actionType}
              onChange={(e) => setActionType(e.target.value as ContainmentActionType)}
              disabled={isPending}
              className="w-full px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            >
              <option value="BLACKLIST_INDICATOR">BLACKLIST_INDICATOR (Domain/URL Dynamic Block)</option>
              <option value="QUARANTINE_TARGET">QUARANTINE_TARGET (Suspend Monitored Asset)</option>
              <option value="INVALIDATE_CACHE">INVALIDATE_CACHE (Purge Threat Cache)</option>
              <option value="CREATE_INCIDENT">CREATE_INCIDENT (Bind or Create Incident)</option>
              <option value="EMIT_SOC_EVENT">EMIT_SOC_EVENT (Record Audited Telemetry Frame)</option>
              <option value="SEND_NOTIFICATION">SEND_NOTIFICATION (Dispatch Emergency Alert)</option>
            </select>
          </div>

          {/* Target Identifier Input */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Target Identifier <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              placeholder="e.g. malicious-c2.com, https://phish.xyz/login, or target-uuid"
              value={targetIdentifier}
              onChange={(e) => setTargetIdentifier(e.target.value)}
              disabled={isPending}
              required
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            />
            <p className="text-2xs text-gray-500 mt-1">
              Evaluated against Rule 0 allowlist invariants. Trusted domains will fail-closed.
            </p>
          </div>

          {/* Optional Alert ID */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Related Alert ID (Optional)
            </label>
            <input
              type="number"
              placeholder="e.g. 1042"
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
              disabled={isPending}
              className="w-full px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            />
          </div>

          {/* Reason Input */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Containment Justification / Reason
            </label>
            <input
              type="text"
              placeholder="Reason for manual containment action..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={isPending}
              maxLength={255}
              className="w-full px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            />
          </div>

          {/* Destructive Warning */}
          {isDestructive && (
            <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-amber-400">
                <AlertTriangle size={14} />
                <span>Destructive Operational Impact</span>
              </div>
              <p className="text-2xs">
                Executing {actionType} will immediately alter tenant traffic rules or disable continuous monitoring probes. This action is audited and can be rolled back via the action drawer.
              </p>
            </div>
          )}

          {/* Footer Controls */}
          <div className="pt-4 border-t border-light-border dark:border-dark-border flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={isPending}
              className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-lg transition-colors disabled:opacity-50"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={isPending || !targetIdentifier.trim()}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isPending && <Loader2 size={14} className="animate-spin" />}
              <span>Confirm & Execute</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
