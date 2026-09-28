/**
 * frontend/src/components/soc/monitoring/TargetDetailDrawer.tsx
 * ─────────────────────────────────────────────────────────────
 * Slide-out diagnostic drawer for Monitored Targets.
 * Displays verified current telemetry (HTTP status, latency, errors, ML confidence)
 * and target configuration metadata.
 */

import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  ExternalLink,
  Globe,
  Loader2,
  Pause,
  Play,
  RotateCcw,
  Server,
  X,
  Zap,
} from 'lucide-react'
import type { MonitoringTarget } from '@/types/soc'
import { monitoringService } from '@/services/soc/monitoring'
import { TargetStatusBadge } from './TargetStatusBadge'
import { clsx } from 'clsx'

export interface TargetDetailDrawerProps {
  target: MonitoringTarget | null
  isOpen: boolean
  onClose: () => void
  onCheckNow: (target: MonitoringTarget) => void
  onTogglePauseResume: (target: MonitoringTarget) => void
  onReactivate: (target: MonitoringTarget) => void
  isCheckingNow: boolean
}

export function TargetDetailDrawer({
  target,
  isOpen,
  onClose,
  onCheckNow,
  onTogglePauseResume,
  onReactivate,
  isCheckingNow,
}: TargetDetailDrawerProps) {
  // Query fresh diagnostic telemetry from GET /v1/monitor/targets/{uuid}/diagnostics
  const { data: diagnostics, isLoading: loadingDiag } = useQuery({
    queryKey: ['monitoring-diagnostics', target?.target_uuid],
    queryFn: () => (target ? monitoringService.getDiagnostics(target.target_uuid) : null),
    enabled: isOpen && Boolean(target),
    staleTime: 15_000,
  })

  if (!isOpen || !target) return null

  const isSuspended = !target.is_active && target.consecutive_failures >= 5
  const isActive = target.is_active

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      return new Date(dateStr).toLocaleString()
    } catch {
      return dateStr
    }
  }

  // Active telemetry values (fallback to target fields if diagnostics query is loading)
  const statusCode = diagnostics?.last_status_code ?? target.last_status_code
  const latencyMs = diagnostics?.last_response_time_ms ?? target.last_response_time_ms
  const errorMessage = diagnostics?.last_error_message ?? target.last_error_message
  const prediction = diagnostics?.last_prediction ?? target.last_prediction
  const confidence = diagnostics?.last_confidence ?? target.last_confidence
  const failures = diagnostics?.consecutive_failures ?? target.consecutive_failures
  const lastChecked = diagnostics?.last_checked_at ?? target.last_checked_at

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex justify-end">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-black/50 backdrop-blur-xs"
        />

        {/* Drawer Panel */}
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 25, stiffness: 200 }}
          className="relative w-full max-w-xl h-full bg-white dark:bg-dark-card border-l border-light-border dark:border-dark-border shadow-2xl z-10 flex flex-col overflow-hidden"
        >
          {/* Header */}
          <div className="p-6 border-b border-light-border dark:border-dark-border/80 flex items-start justify-between gap-4 bg-light-surface/40 dark:bg-dark-surface/40">
            <div className="space-y-1.5 flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <TargetStatusBadge
                  isActive={target.is_active}
                  consecutiveFailures={failures}
                />
                <span className="text-3xs font-mono text-gray-400 truncate">
                  UUID: {target.target_uuid}
                </span>
              </div>
              <h2 className="text-base font-bold text-gray-900 dark:text-white truncate flex items-center gap-1.5">
                <Globe size={16} className="text-primary-400 shrink-0" />
                <span className="truncate">{target.normalized_domain || target.url}</span>
              </h2>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors shrink-0"
              aria-label="Close Drawer"
            >
              <X size={18} />
            </button>
          </div>

          {/* Drawer Body */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
            {/* Current Diagnostic Telemetry Card */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Activity size={13} className="text-primary-400" />
                  <span>Execution Diagnostics Telemetry</span>
                </h3>
                {loadingDiag && (
                  <span className="text-3xs text-gray-400 flex items-center gap-1">
                    <Loader2 size={11} className="animate-spin" />
                    <span>Polling...</span>
                  </span>
                )}
              </div>

              <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-surface/50 border border-light-border dark:border-dark-border space-y-4">
                {/* Metric Grid */}
                <div className="grid grid-cols-2 gap-3 text-2xs">
                  {/* HTTP Status Code */}
                  <div className="p-3 rounded-lg bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border">
                    <span className="text-gray-500 block">HTTP Response Code:</span>
                    <span
                      className={clsx(
                        'text-sm font-bold font-mono',
                        statusCode && statusCode >= 200 && statusCode < 300
                          ? 'text-emerald-400'
                          : statusCode && statusCode >= 400
                          ? 'text-rose-400'
                          : 'text-gray-400'
                      )}
                    >
                      {statusCode ? `HTTP ${statusCode}` : 'No response'}
                    </span>
                  </div>

                  {/* Round-trip Latency */}
                  <div className="p-3 rounded-lg bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border">
                    <span className="text-gray-500 block">Response Latency:</span>
                    <span className="text-sm font-bold font-mono text-gray-800 dark:text-gray-200">
                      {latencyMs !== null && latencyMs !== undefined
                        ? `${Math.round(latencyMs)} ms`
                        : '—'}
                    </span>
                  </div>

                  {/* ML Threat Prediction */}
                  <div className="p-3 rounded-lg bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border">
                    <span className="text-gray-500 block">AI Security Verdict:</span>
                    <span className="text-sm font-bold text-gray-800 dark:text-gray-200">
                      {prediction || 'Pending analysis'}
                    </span>
                    {confidence && (
                      <span className="text-3xs text-gray-400 block mt-0.5">
                        Confidence: {Math.round(confidence * 100)}%
                      </span>
                    )}
                  </div>

                  {/* Consecutive Failures */}
                  <div className="p-3 rounded-lg bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border">
                    <span className="text-gray-500 block">Failure Counter:</span>
                    <span
                      className={clsx(
                        'text-sm font-bold font-mono',
                        failures >= 5
                          ? 'text-rose-400'
                          : failures > 0
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      )}
                    >
                      {failures} consecutive fail(s)
                    </span>
                    <span className="text-3xs text-gray-400 block mt-0.5">
                      {failures >= 5
                        ? 'Auto-suspended'
                        : `${5 - failures} failures until suspension`}
                    </span>
                  </div>
                </div>

                {/* Error diagnostics banner if present */}
                {errorMessage && (
                  <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-2xs space-y-1">
                    <div className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-3xs">
                      <AlertTriangle size={12} />
                      <span>Probe Failure Diagnostics:</span>
                    </div>
                    <p className="font-mono text-3xs leading-relaxed break-words">
                      {errorMessage}
                    </p>
                  </div>
                )}

                <div className="pt-2 border-t border-light-border dark:border-dark-border/60 text-2xs text-gray-500 flex items-center justify-between">
                  <span>Last Executed:</span>
                  <span className="text-gray-800 dark:text-gray-200 font-medium">
                    {formatDate(lastChecked)}
                  </span>
                </div>
              </div>
            </div>

            {/* Target Fleet Configuration Card */}
            <div className="space-y-2">
              <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                <Server size={13} className="text-primary-400" />
                <span>Configuration & Scheduling</span>
              </h3>

              <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-surface/50 border border-light-border dark:border-dark-border space-y-3">
                <div>
                  <span className="text-3xs text-gray-500 block font-bold uppercase tracking-wider mb-1">
                    Full Target URL:
                  </span>
                  <div className="flex items-center gap-2 p-2 rounded-lg bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border">
                    <span className="font-mono text-2xs text-primary-400 break-all flex-1 select-all">
                      {target.url}
                    </span>
                    <a
                      href={target.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-white p-1 rounded-md transition-colors shrink-0"
                      title="Open URL in new tab"
                    >
                      <ExternalLink size={13} />
                    </a>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 text-2xs pt-1">
                  <div>
                    <span className="text-gray-500 block">Check Interval:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium font-mono">
                      Every {target.check_interval_minutes} minutes
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 block">Next Scheduled Check:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium font-mono">
                      {target.is_active ? formatDate(target.next_check_at) : 'Inactive'}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 block">Registered At:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium">
                      {formatDate(target.created_at)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 block">Owner User ID:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium font-mono">
                      User #{target.user_id}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Drawer Actions Footer */}
          <div className="p-4 border-t border-light-border dark:border-dark-border/80 bg-light-surface/40 dark:bg-dark-surface/40 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {/* Check Now */}
              {target.is_active && (
                <button
                  type="button"
                  onClick={() => onCheckNow(target)}
                  disabled={isCheckingNow}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-50 transition-colors shadow-xs"
                >
                  {isCheckingNow ? (
                    <Loader2 size={13} className="animate-spin" />
                  ) : (
                    <Zap size={13} />
                  )}
                  <span>Check Now</span>
                </button>
              )}

              {/* Pause / Resume */}
              {!isSuspended && (
                <button
                  type="button"
                  onClick={() => onTogglePauseResume(target)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-700 dark:text-gray-200 border border-light-border dark:border-dark-border hover:bg-light-hover dark:hover:bg-dark-hover transition-colors"
                >
                  {isActive ? <Pause size={13} /> : <Play size={13} />}
                  <span>{isActive ? 'Pause' : 'Resume'}</span>
                </button>
              )}

              {/* Reactivate */}
              {(isSuspended || failures > 0) && (
                <button
                  type="button"
                  onClick={() => onReactivate(target)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-300 bg-emerald-500/15 border border-emerald-500/30 hover:bg-emerald-500/25 transition-colors"
                >
                  <RotateCcw size={13} />
                  <span>Reactivate</span>
                </button>
              )}
            </div>

            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors font-medium text-xs"
            >
              Close Drawer
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
