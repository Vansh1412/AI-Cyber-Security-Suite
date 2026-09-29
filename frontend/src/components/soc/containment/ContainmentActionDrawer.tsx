/**
 * frontend/src/components/soc/containment/ContainmentActionDrawer.tsx
 * ──────────────────────────────────────────────────────────────────
 * Slide-out detail drawer inspecting a containment action's full telemetry,
 * execution provenance, idempotency keys, and rollback metadata.
 */

import React from 'react'
import {
  AlertTriangle,
  Code2,
  ExternalLink,
  RotateCcw,
  ShieldAlert,
  X,
} from 'lucide-react'
import type { ContainmentActionResponse } from '@/types/soc'

export interface ContainmentActionDrawerProps {
  action: ContainmentActionResponse | null
  isOpen: boolean
  onClose: () => void
  onRevert: (action: ContainmentActionResponse) => void
  isReverting?: boolean
}

export function ContainmentActionDrawer({
  action,
  isOpen,
  onClose,
  onRevert,
  isReverting = false,
}: ContainmentActionDrawerProps) {
  if (!isOpen || !action) return null

  const isReversible =
    action.status === 'EXECUTED' &&
    (action.action_type === 'BLACKLIST_INDICATOR' || action.action_type === 'QUARANTINE_TARGET')

  const formatTimestamp = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      return new Date(dateStr).toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium',
      })
    } catch {
      return dateStr
    }
  }

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-200">
      <div
        className="w-full max-w-xl bg-white dark:bg-dark-surface border-l border-light-border dark:border-dark-border h-full flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border flex items-start justify-between gap-4 bg-gray-50/50 dark:bg-dark-bg/50">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-primary-500/10 text-primary-400 border border-primary-500/20">
                {action.action_type}
              </span>
              <span className="text-2xs font-mono text-gray-500">
                ID #{action.id}
              </span>
            </div>
            <h2 className="text-lg font-bold text-gray-900 dark:text-white break-all">
              {action.target_identifier}
            </h2>
            <p className="text-2xs font-mono text-gray-400 mt-1">
              UUID: {action.action_uuid}
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
            title="Close Drawer"
            aria-label="Close action drawer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Drawer Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Rule 0 Allowlist Banner */}
          {action.status === 'BLOCKED_BY_ALLOWLIST' && (
            <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-1.5">
              <div className="flex items-center gap-2 font-semibold text-amber-400">
                <ShieldAlert size={16} />
                <span>Rule 0 Allowlist Invariant Enforced</span>
              </div>
              <p>
                The indicator <code className="font-mono text-white">{action.target_identifier}</code> is recognized by the Threat Intelligence allowlist as legitimate trusted infrastructure. Containment was fail-closed to prevent accidental denial of service.
              </p>
            </div>
          )}

          {/* Failure Alert */}
          {action.status === 'FAILED' && action.error_message && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs space-y-1.5">
              <div className="flex items-center gap-2 font-semibold text-rose-400">
                <AlertTriangle size={16} />
                <span>Containment Execution Error</span>
              </div>
              <p className="font-mono break-all">{action.error_message}</p>
            </div>
          )}

          {/* Primary Telemetry */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Execution Details
            </h3>

            <div className="grid grid-cols-2 gap-3 text-xs bg-gray-50 dark:bg-dark-bg/40 p-4 rounded-xl border border-light-border dark:border-dark-border">
              <div>
                <span className="text-gray-400 block text-2xs">Status</span>
                <span className="font-semibold text-gray-900 dark:text-white capitalize">
                  {action.status.toLowerCase()}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Trigger Source</span>
                <span className="font-medium text-gray-900 dark:text-white capitalize">
                  {action.trigger_source.replace(/_/g, ' ')}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Created At</span>
                <span className="text-gray-700 dark:text-gray-300">
                  {formatTimestamp(action.created_at)}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Completed At</span>
                <span className="text-gray-700 dark:text-gray-300">
                  {formatTimestamp(action.completed_at)}
                </span>
              </div>
              {action.actor_user_id && (
                <div>
                  <span className="text-gray-400 block text-2xs">Actor User ID</span>
                  <span className="text-gray-700 dark:text-gray-300">
                    User #{action.actor_user_id}
                  </span>
                </div>
              )}
              {action.alert_id && (
                <div>
                  <span className="text-gray-400 block text-2xs">Triggering Alert</span>
                  <a
                    href={`/soc/alerts?search=${action.alert_id}`}
                    className="inline-flex items-center gap-1 text-primary-400 hover:underline"
                  >
                    Alert #{action.alert_id}
                    <ExternalLink size={11} />
                  </a>
                </div>
              )}
              {action.incident_id && (
                <div>
                  <span className="text-gray-400 block text-2xs">Bound Incident</span>
                  <a
                    href={`/soc/incidents?search=${action.incident_id}`}
                    className="inline-flex items-center gap-1 text-purple-400 hover:underline"
                  >
                    Incident #{action.incident_id}
                    <ExternalLink size={11} />
                  </a>
                </div>
              )}
              {action.expires_at && (
                <div>
                  <span className="text-gray-400 block text-2xs">TTL Expiration</span>
                  <span className="text-gray-700 dark:text-gray-300">
                    {formatTimestamp(action.expires_at)}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Rollback Details (if reverted) */}
          {action.reverted_at && (
            <div className="space-y-3">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                Rollback Provenance
              </h3>
              <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/20 text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-purple-300 font-medium">Reverted At</span>
                  <span className="text-gray-300">{formatTimestamp(action.reverted_at)}</span>
                </div>
                {action.reverted_by_user_id && (
                  <div className="flex items-center justify-between">
                    <span className="text-purple-300 font-medium">Reverted By</span>
                    <span className="text-gray-300">User #{action.reverted_by_user_id}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Result Metadata */}
          {action.result_metadata && Object.keys(action.result_metadata).length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
                <Code2 size={13} />
                Result Metadata
              </h3>
              <pre className="p-3.5 rounded-xl bg-gray-50 dark:bg-dark-bg text-2xs font-mono text-gray-800 dark:text-gray-200 border border-light-border dark:border-dark-border overflow-x-auto">
                {JSON.stringify(action.result_metadata, null, 2)}
              </pre>
            </div>
          )}

          {/* Rollback Metadata */}
          {action.rollback_metadata && Object.keys(action.rollback_metadata).length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
                <RotateCcw size={13} />
                Rollback Parameters
              </h3>
              <pre className="p-3.5 rounded-xl bg-gray-50 dark:bg-dark-bg text-2xs font-mono text-gray-800 dark:text-gray-200 border border-light-border dark:border-dark-border overflow-x-auto">
                {JSON.stringify(action.rollback_metadata, null, 2)}
              </pre>
            </div>
          )}

          {/* Idempotency Key */}
          <div className="space-y-1.5">
            <span className="text-2xs font-semibold text-gray-500 uppercase tracking-wider">
              Exact Idempotency Key
            </span>
            <p className="p-2.5 rounded-lg bg-gray-50 dark:bg-dark-bg font-mono text-2xs text-gray-500 break-all border border-light-border dark:border-dark-border">
              {action.action_idempotency_key}
            </p>
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="p-4 border-t border-light-border dark:border-dark-border bg-gray-50/50 dark:bg-dark-bg/50 flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-lg transition-colors"
          >
            Close
          </button>

          {isReversible && (
            <button
              type="button"
              disabled={isReverting}
              onClick={() => onRevert(action)}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white transition-all disabled:opacity-50 shadow-sm"
            >
              <RotateCcw size={14} className={isReverting ? 'animate-spin' : ''} />
              <span>Rollback Action</span>
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
