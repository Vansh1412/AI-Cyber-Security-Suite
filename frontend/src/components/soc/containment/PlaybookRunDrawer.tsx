/**
 * frontend/src/components/soc/containment/PlaybookRunDrawer.tsx
 * ────────────────────────────────────────────────────────────
 * Detail drawer for inspecting a SOAR Playbook run, fencing token,
 * error state, and associated child containment actions.
 */

import React from 'react'
import {
  AlertTriangle,
  Layers,
  X,
} from 'lucide-react'
import type { PlaybookRunResponse } from '@/types/soc'

export interface PlaybookRunDrawerProps {
  run: PlaybookRunResponse | null
  isOpen: boolean
  onClose: () => void
}

export function PlaybookRunDrawer({ run, isOpen, onClose }: PlaybookRunDrawerProps) {
  if (!isOpen || !run) return null

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
        className="w-full max-w-lg bg-white dark:bg-dark-surface border-l border-light-border dark:border-dark-border h-full flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-light-border dark:border-dark-border flex items-start justify-between gap-4 bg-gray-50/50 dark:bg-dark-bg/50">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-primary-500/10 text-primary-400 border border-primary-500/20">
                v{run.playbook_version}
              </span>
              <span className="text-2xs font-mono text-gray-500">
                Fencing #{run.fencing_token}
              </span>
            </div>
            <h2 className="text-lg font-bold text-gray-900 dark:text-white">
              {run.playbook_name}
            </h2>
            <p className="text-2xs font-mono text-gray-400 mt-1">
              UUID: {run.run_uuid}
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
            title="Close Drawer"
            aria-label="Close playbook drawer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Error Message */}
          {run.error_message && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300 space-y-1">
              <div className="flex items-center gap-2 font-semibold text-rose-400">
                <AlertTriangle size={15} />
                <span>Playbook Run Error</span>
              </div>
              <p className="font-mono">{run.error_message}</p>
            </div>
          )}

          {/* Telemetry Grid */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Execution Telemetry
            </h3>

            <div className="grid grid-cols-2 gap-3 text-xs bg-gray-50 dark:bg-dark-bg/40 p-4 rounded-xl border border-light-border dark:border-dark-border">
              <div>
                <span className="text-gray-400 block text-2xs">Status</span>
                <span className="font-semibold text-gray-900 dark:text-white uppercase">
                  {run.status}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Trigger Event</span>
                <span className="font-mono text-gray-900 dark:text-white">
                  {run.trigger_event}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Started At</span>
                <span className="text-gray-700 dark:text-gray-300">
                  {formatTimestamp(run.started_at)}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Completed At</span>
                <span className="text-gray-700 dark:text-gray-300">
                  {formatTimestamp(run.completed_at)}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Actions Completed</span>
                <span className="font-semibold text-primary-400">
                  {run.action_count}
                </span>
              </div>
              <div>
                <span className="text-gray-400 block text-2xs">Distributed Fencing Token</span>
                <span className="font-mono text-gray-700 dark:text-gray-300">
                  {run.fencing_token}
                </span>
              </div>
            </div>
          </div>

          {/* Child Actions */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
              <Layers size={14} />
              <span>Executed Action Steps ({run.actions?.length || 0})</span>
            </h3>

            {run.actions && run.actions.length > 0 ? (
              <div className="space-y-2">
                {run.actions.map((act) => (
                  <div
                    key={act.action_uuid}
                    className="p-3 rounded-lg border border-light-border dark:border-dark-border bg-gray-50/50 dark:bg-dark-bg/50 flex items-center justify-between text-xs"
                  >
                    <div>
                      <span className="font-semibold text-gray-900 dark:text-white">
                        {act.action_type}
                      </span>
                      <p className="text-2xs text-gray-400 font-mono">
                        {act.target_identifier}
                      </p>
                    </div>
                    <span className="px-2 py-0.5 rounded text-2xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {act.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500 italic p-3 rounded-lg bg-gray-50 dark:bg-dark-bg/20 border border-light-border dark:border-dark-border">
                No child action records attached.
              </p>
            )}
          </div>

          {/* Idempotency Key */}
          <div className="space-y-1.5">
            <span className="text-2xs font-semibold text-gray-500 uppercase tracking-wider">
              Playbook Idempotency Key
            </span>
            <p className="p-2.5 rounded-lg bg-gray-50 dark:bg-dark-bg font-mono text-2xs text-gray-500 break-all border border-light-border dark:border-dark-border">
              {run.idempotency_key}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-light-border dark:border-dark-border bg-gray-50/50 dark:bg-dark-bg/50 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
