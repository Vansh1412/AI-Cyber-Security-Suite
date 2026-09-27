/**
 * frontend/src/components/soc/alerts/AlertDetailDrawer.tsx
 * ─────────────────────────────────────────────────────────
 * Slide-over drawer presenting comprehensive alert diagnostics, telemetry timeline, and actions.
 */

import React, { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Clock,
  Copy,
  ExternalLink,
  Flame,
  Hash,
  Layers,
  RotateCcw,
  X,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Alert } from '@/types/soc'
import { SeverityBadge } from './SeverityBadge'

export interface AlertDetailDrawerProps {
  alert: Alert | null
  isOpen: boolean
  onClose: () => void
  onAcknowledge: (alert: Alert) => void
  onResolve: (alert: Alert) => void
  onDismiss: (alert: Alert) => void
  onReopen: (alert: Alert) => void
  onEscalate: (alert: Alert) => void
}

export function AlertDetailDrawer({
  alert,
  isOpen,
  onClose,
  onAcknowledge,
  onResolve,
  onDismiss,
  onReopen,
  onEscalate,
}: AlertDetailDrawerProps) {
  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!alert) return null

  const isSafeUrl =
    alert.indicator_value.startsWith('http://') || alert.indicator_value.startsWith('https://')

  const copyText = (val: string, label: string) => {
    navigator.clipboard.writeText(val)
    toast.success(`${label} copied to clipboard`, { duration: 1500 })
  }

  const formatUtc = (isoString?: string | null) => {
    if (!isoString) return '—'
    try {
      return new Date(isoString).toLocaleString()
    } catch {
      return isoString
    }
  }

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40"
          />

          {/* Slide-over panel */}
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 28, stiffness: 300 }}
            className="fixed right-0 top-0 bottom-0 w-full max-w-xl bg-dark-card border-l border-dark-border z-50 flex flex-col shadow-2xl overflow-hidden"
          >
            {/* Header */}
            <div className="p-5 border-b border-dark-border flex items-start justify-between gap-3 bg-dark-surface/40">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <span className="text-2xs font-mono text-gray-500 uppercase">
                    Status: <strong className="text-gray-300">{alert.status}</strong>
                  </span>
                  {alert.incident_id && (
                    <span className="px-2 py-0.5 rounded text-3xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      INCIDENT #{alert.incident_id}
                    </span>
                  )}
                </div>
                <h2 className="text-base font-bold text-white leading-snug">{alert.title}</h2>
                <div className="flex items-center gap-2 text-2xs font-mono text-gray-400">
                  <span>UUID: {alert.alert_uuid}</span>
                  <button
                    type="button"
                    onClick={() => copyText(alert.alert_uuid, 'UUID')}
                    className="p-0.5 hover:text-white text-gray-500 rounded"
                    title="Copy Alert UUID"
                  >
                    <Copy size={11} />
                  </button>
                </div>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors shrink-0"
                title="Close drawer (Esc)"
              >
                <X size={18} />
              </button>
            </div>

            {/* Scrollable Content */}
            <div className="flex-1 overflow-y-auto p-5 space-y-5">
              {/* Threat Indicator Box */}
              <div className="p-4 rounded-xl bg-dark-surface/60 border border-dark-border space-y-2">
                <div className="flex items-center justify-between text-2xs text-gray-400 font-semibold uppercase">
                  <span>Threat Indicator</span>
                  <span className="px-1.5 py-0.5 rounded bg-primary-500/10 text-primary-400 border border-primary-500/20">
                    {alert.indicator_type}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-dark-bg/80 border border-dark-border font-mono text-xs text-rose-300 break-all select-all flex items-start justify-between gap-2">
                  <span>{alert.indicator_value}</span>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => copyText(alert.indicator_value, 'Indicator')}
                      className="p-1 hover:text-white text-gray-500 rounded"
                      title="Copy indicator"
                    >
                      <Copy size={13} />
                    </button>
                    {isSafeUrl && (
                      <a
                        href={alert.indicator_value}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1 hover:text-primary-400 text-gray-500 rounded"
                        title="Open in new window"
                      >
                        <ExternalLink size={13} />
                      </a>
                    )}
                  </div>
                </div>
                {alert.fingerprint && (
                  <div className="flex items-center gap-1.5 text-3xs font-mono text-gray-500 truncate pt-1">
                    <Hash size={11} />
                    <span>Fingerprint: {alert.fingerprint}</span>
                  </div>
                )}
              </div>

              {/* Description */}
              {alert.description && (
                <div className="space-y-1">
                  <h3 className="text-2xs font-semibold uppercase tracking-wider text-gray-400">
                    Description & Context
                  </h3>
                  <p className="text-xs text-gray-300 bg-dark-surface/40 p-3 rounded-xl border border-dark-border leading-relaxed">
                    {alert.description}
                  </p>
                </div>
              )}

              {/* Detection Metadata */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-dark-surface/40 border border-dark-border space-y-1">
                  <span className="text-2xs text-gray-500 font-semibold uppercase">Detection Rule</span>
                  <p className="font-mono text-white text-xs truncate" title={alert.rule_name}>
                    {alert.rule_name}
                  </p>
                </div>
                <div className="p-3 rounded-xl bg-dark-surface/40 border border-dark-border space-y-1">
                  <span className="text-2xs text-gray-500 font-semibold uppercase">Events Suppressed</span>
                  <div className="flex items-center gap-1.5 text-white font-mono text-xs">
                    <Layers size={13} className="text-purple-400" />
                    <span>{alert.occurrence_count.toLocaleString()} occurrences</span>
                  </div>
                </div>
              </div>

              {/* Event Timeline */}
              <div className="space-y-2">
                <h3 className="text-2xs font-semibold uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                  <Clock size={12} />
                  <span>Lifecycle Timeline</span>
                </h3>
                <div className="p-3 rounded-xl bg-dark-surface/40 border border-dark-border space-y-2 text-xs">
                  <div className="flex justify-between items-center text-2xs">
                    <span className="text-gray-400">First Ingested:</span>
                    <span className="font-mono text-gray-200">{formatUtc(alert.first_seen_at)}</span>
                  </div>
                  <div className="flex justify-between items-center text-2xs border-t border-dark-border/40 pt-1.5">
                    <span className="text-gray-400">Last Seen:</span>
                    <span className="font-mono text-white font-semibold">{formatUtc(alert.last_seen_at)}</span>
                  </div>
                  {alert.acknowledged_at && (
                    <div className="flex justify-between items-center text-2xs border-t border-dark-border/40 pt-1.5">
                      <span className="text-purple-400">Claimed:</span>
                      <span className="font-mono text-gray-200">{formatUtc(alert.acknowledged_at)}</span>
                    </div>
                  )}
                  {alert.resolved_at && (
                    <div className="flex justify-between items-center text-2xs border-t border-dark-border/40 pt-1.5">
                      <span className="text-emerald-400">Resolved:</span>
                      <span className="font-mono text-gray-200">{formatUtc(alert.resolved_at)}</span>
                    </div>
                  )}
                  {alert.dismissed_at && (
                    <div className="flex justify-between items-center text-2xs border-t border-dark-border/40 pt-1.5">
                      <span className="text-gray-400">Dismissed:</span>
                      <span className="font-mono text-gray-200">{formatUtc(alert.dismissed_at)}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Triage / Dismissal Notes */}
              {(alert.dismiss_reason || alert.triage_notes) && (
                <div className="space-y-2">
                  <h3 className="text-2xs font-semibold uppercase tracking-wider text-gray-400">
                    Triage Rationale & Notes
                  </h3>
                  <div className="p-3 rounded-xl bg-dark-surface/40 border border-dark-border space-y-2 text-xs">
                    {alert.dismiss_reason && (
                      <div>
                        <span className="text-2xs text-gray-500 font-semibold uppercase">Dismissal Reason:</span>
                        <p className="text-white font-medium mt-0.5">{alert.dismiss_reason}</p>
                      </div>
                    )}
                    {alert.triage_notes && (
                      <div className={alert.dismiss_reason ? 'border-t border-dark-border/40 pt-2' : ''}>
                        <span className="text-2xs text-gray-500 font-semibold uppercase">Analyst Notes:</span>
                        <p className="text-gray-300 mt-0.5 whitespace-pre-wrap">{alert.triage_notes}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Sticky Actions Footer */}
            <div className="p-4 border-t border-dark-border bg-dark-surface/60 flex items-center justify-between gap-2">
              <div className="flex items-center gap-1.5">
                {alert.status === 'OPEN' && (
                  <button
                    type="button"
                    onClick={() => onAcknowledge(alert)}
                    className="btn-primary py-2 px-3.5 text-xs"
                  >
                    Claim & Acknowledge
                  </button>
                )}

                {(alert.status === 'OPEN' || alert.status === 'ACKNOWLEDGED') && (
                  <>
                    <button
                      type="button"
                      onClick={() => onResolve(alert)}
                      className="px-3 py-2 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 rounded-xl text-xs font-semibold transition-colors"
                    >
                      Resolve
                    </button>
                    <button
                      type="button"
                      onClick={() => onDismiss(alert)}
                      className="px-3 py-2 bg-gray-500/15 hover:bg-gray-500/25 text-gray-300 border border-gray-500/30 rounded-xl text-xs font-semibold transition-colors"
                    >
                      Dismiss
                    </button>
                  </>
                )}

                {(alert.status === 'RESOLVED' || alert.status === 'DISMISSED') && (
                  <button
                    type="button"
                    onClick={() => onReopen(alert)}
                    className="inline-flex items-center gap-1.5 px-3 py-2 bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 rounded-xl text-xs font-semibold transition-colors"
                  >
                    <RotateCcw size={12} />
                    Reopen Alert
                  </button>
                )}
              </div>

              <button
                type="button"
                onClick={() => onEscalate(alert)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 rounded-xl text-xs font-semibold transition-colors ml-auto"
              >
                <Flame size={13} />
                Escalate to Incident
              </button>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  )
}
