/**
 * frontend/src/components/soc/alerts/TriageActionModal.tsx
 * ─────────────────────────────────────────────────────────
 * Modal dialog for Acknowledge, Resolve, Dismiss (with mandatory reason validation), and Reopen.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, Loader2, RotateCcw, ShieldAlert, X, XCircle } from 'lucide-react'
import type { Alert } from '@/types/soc'

export type TriageActionType = 'acknowledge' | 'resolve' | 'dismiss' | 'reopen'

export interface TriageActionModalProps {
  alert: Alert | null
  actionType: TriageActionType | null
  isOpen: boolean
  onClose: () => void
  onSubmit: (payload: {
    notes?: string
    resolution_notes?: string
    dismiss_reason?: string
    triage_notes?: string
    reopen_notes?: string
  }) => Promise<void>
  isSubmitting: boolean
}

const DISMISS_REASON_OPTIONS = [
  'False Positive — Legitimate Domain / Indicator',
  'Internal Testing / Authorized Pentest Activity',
  'Risk Accepted / Benign Low-Impact Behavior',
  'Duplicate Indicator / Noise Reduction',
  'Other (Custom Justification)',
]

export function TriageActionModal({
  alert,
  actionType,
  isOpen,
  onClose,
  onSubmit,
  isSubmitting,
}: TriageActionModalProps) {
  const [notes, setNotes] = useState('')
  const [selectedDismissReason, setSelectedDismissReason] = useState(DISMISS_REASON_OPTIONS[0])
  const [customDismissReason, setCustomDismissReason] = useState('')

  useEffect(() => {
    if (isOpen) {
      setNotes('')
      setSelectedDismissReason(DISMISS_REASON_OPTIONS[0])
      setCustomDismissReason('')
    }
  }, [isOpen])

  if (!isOpen || !alert || !actionType) return null

  const isCustomReason = selectedDismissReason === 'Other (Custom Justification)'
  const effectiveDismissReason = isCustomReason ? customDismissReason.trim() : selectedDismissReason.trim()
  const isDismissDisabled = actionType === 'dismiss' && !effectiveDismissReason

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (isDismissDisabled || isSubmitting) return

    if (actionType === 'acknowledge') {
      await onSubmit({ notes: notes.trim() || undefined })
    } else if (actionType === 'resolve') {
      await onSubmit({ resolution_notes: notes.trim() || undefined })
    } else if (actionType === 'dismiss') {
      await onSubmit({
        dismiss_reason: effectiveDismissReason,
        triage_notes: notes.trim() || undefined,
      })
    } else if (actionType === 'reopen') {
      await onSubmit({ reopen_notes: notes.trim() || undefined })
    }
  }

  const getConfig = () => {
    switch (actionType) {
      case 'acknowledge':
        return {
          title: 'Claim & Acknowledge Alert',
          subtitle: 'Acknowledge ownership and claim this alert for active analyst investigation.',
          icon: ShieldAlert,
          iconColor: 'text-primary-400',
          iconBg: 'bg-primary-500/15',
          btnClass: 'btn-primary',
          btnText: 'Claim Alert',
        }
      case 'resolve':
        return {
          title: 'Resolve Security Alert',
          subtitle: 'Transition this alert to RESOLVED following containment or verification of safe state.',
          icon: CheckCircle2,
          iconColor: 'text-emerald-400',
          iconBg: 'bg-emerald-500/15',
          btnClass: 'px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-xl transition-all',
          btnText: 'Confirm Resolution',
        }
      case 'dismiss':
        return {
          title: 'Dismiss Alert as False Positive / Benign',
          subtitle: 'Dismiss this alert from active triage. A valid justification reason is mandatory.',
          icon: XCircle,
          iconColor: 'text-gray-400',
          iconBg: 'bg-gray-500/15',
          btnClass: 'px-5 py-2.5 bg-gray-600 hover:bg-gray-500 text-white font-semibold rounded-xl transition-all',
          btnText: 'Dismiss Alert',
        }
      case 'reopen':
      default:
        return {
          title: 'Reopen Security Alert',
          subtitle: 'Move this alert back into the active OPEN triage pool for reassessment.',
          icon: RotateCcw,
          iconColor: 'text-amber-400',
          iconBg: 'bg-amber-500/15',
          btnClass: 'px-5 py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-semibold rounded-xl transition-all',
          btnText: 'Reopen to Triage Pool',
        }
    }
  }

  const config = getConfig()
  const Icon = config.icon

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="fixed inset-0 bg-black/60 backdrop-blur-xs"
        />

        {/* Modal Window */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="relative w-full max-w-lg bg-dark-card border border-dark-border rounded-2xl shadow-2xl p-6 z-10 space-y-5"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${config.iconBg}`}>
                <Icon size={20} className={config.iconColor} />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">{config.title}</h3>
                <p className="text-2xs text-gray-400 mt-0.5">{config.subtitle}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded-lg text-gray-500 hover:text-white hover:bg-dark-hover"
            >
              <X size={16} />
            </button>
          </div>

          {/* Alert Context Summary */}
          <div className="p-3 rounded-xl bg-dark-surface/60 border border-dark-border text-xs space-y-1">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-white truncate max-w-[280px]">{alert.title}</span>
              <span className="font-mono text-3xs text-gray-400">UUID: {alert.alert_uuid.slice(0, 8)}...</span>
            </div>
            <p className="font-mono text-2xs text-gray-400 truncate">{alert.indicator_value}</p>
          </div>

          {/* Form */}
          <form onSubmit={handleFormSubmit} className="space-y-4 text-xs">
            {/* Dismissal Reason Selector (Mandatory for dismiss) */}
            {actionType === 'dismiss' && (
              <div className="space-y-2">
                <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                  Dismissal Reason <span className="text-rose-400">*</span>
                </label>
                <select
                  value={selectedDismissReason}
                  onChange={(e) => setSelectedDismissReason(e.target.value)}
                  className="w-full px-3 py-2.5 bg-dark-surface border border-dark-border rounded-xl text-xs text-white focus:outline-none focus:border-primary-500 transition-colors cursor-pointer"
                >
                  {DISMISS_REASON_OPTIONS.map((opt) => (
                    <option key={opt} value={opt} className="bg-dark-surface text-white">
                      {opt}
                    </option>
                  ))}
                </select>

                {isCustomReason && (
                  <input
                    type="text"
                    value={customDismissReason}
                    onChange={(e) => setCustomDismissReason(e.target.value)}
                    placeholder="Specify non-empty dismissal reason..."
                    className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-white placeholder-gray-500 focus:outline-none focus:border-primary-500 mt-2"
                    required
                  />
                )}
              </div>
            )}

            {/* Notes / Rationale Field */}
            <div className="space-y-1.5">
              <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                {actionType === 'resolve'
                  ? 'Resolution Notes (Optional)'
                  : actionType === 'reopen'
                  ? 'Reopen Reason (Optional)'
                  : 'Analyst Notes (Optional)'}
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Add contextual findings, verification steps, or rationale..."
                rows={3}
                className="w-full px-3 py-2.5 bg-dark-surface border border-dark-border rounded-xl text-xs text-white placeholder-gray-500 focus:outline-none focus:border-primary-500 resize-none transition-colors"
              />
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-dark-border">
              <button
                type="button"
                disabled={isSubmitting}
                onClick={onClose}
                className="btn-ghost text-xs py-2 px-4"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isDismissDisabled || isSubmitting}
                className={`${config.btnClass} text-xs py-2 px-4 disabled:opacity-40 disabled:pointer-events-none inline-flex items-center gap-1.5`}
              >
                {isSubmitting && <Loader2 size={13} className="animate-spin" />}
                <span>{config.btnText}</span>
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
