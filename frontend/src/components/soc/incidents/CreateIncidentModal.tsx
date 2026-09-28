/**
 * frontend/src/components/soc/incidents/CreateIncidentModal.tsx
 * ──────────────────────────────────────────────────────────────
 * Modal for creating a new Security Incident case.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertOctagon, CheckCircle2, Loader2, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { EventSeverity } from '@/types/soc'
import { incidentsService } from '@/services/soc/incidents'

export interface CreateIncidentModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

const SEVERITIES: { value: EventSeverity; label: string }[] = [
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
  { value: 'INFO', label: 'Info' },
]

export function CreateIncidentModal({
  isOpen,
  onClose,
  onSuccess,
}: CreateIncidentModalProps) {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<EventSeverity>('HIGH')
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (isOpen) {
      setTitle('')
      setDescription('')
      setSeverity('HIGH')
      setIsSubmitting(false)
    }
  }, [isOpen])

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim() || isSubmitting) return

    setIsSubmitting(true)
    try {
      await incidentsService.createIncident({
        title: title.trim(),
        description: description.trim() || undefined,
        severity,
      })
      toast.success('Security incident created successfully.')
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const msg = errorObj?.response?.data?.detail
      toast.error(typeof msg === 'string' ? msg : 'Failed to create incident.')
    } finally {
      setIsSubmitting(false)
    }
  }

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
          className="relative w-full max-w-lg bg-white dark:bg-dark-card border border-light-border dark:border-dark-border rounded-2xl shadow-2xl p-6 z-10 space-y-4"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-primary-500/15 flex items-center justify-center text-primary-400 shrink-0">
                <AlertOctagon size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white">
                  Create Security Incident
                </h3>
                <p className="text-2xs text-gray-500 mt-0.5">
                  Initialize a new coordinated case container.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-dark-hover transition-colors"
              aria-label="Close"
            >
              <X size={18} />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {/* Title */}
            <div className="space-y-1.5">
              <label htmlFor="create-incident-title" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Incident Title <span className="text-rose-400">*</span>
              </label>
              <input
                id="create-incident-title"
                type="text"
                required
                maxLength={255}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g., Coordinated Credential Phishing Campaign on Internal Gateway"
                className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl px-3 py-2.5 focus:outline-hidden focus:border-primary-500 transition-colors"
              />
            </div>

            {/* Severity */}
            <div className="space-y-1.5">
              <label htmlFor="create-incident-severity" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Initial Severity <span className="text-rose-400">*</span>
              </label>
              <select
                id="create-incident-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as EventSeverity)}
                className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl px-3 py-2.5 focus:outline-hidden focus:border-primary-500 transition-colors"
              >
                {SEVERITIES.map((s) => (
                  <option key={s.value} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <label htmlFor="create-incident-desc" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Description & Scope
              </label>
              <textarea
                id="create-incident-desc"
                rows={4}
                maxLength={5000}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Describe suspected threat vector, initial indicators, and impact scope..."
                className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl p-3 focus:outline-hidden focus:border-primary-500 transition-colors resize-none"
              />
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-2 pt-2 border-t border-light-border dark:border-dark-border/60">
              <button
                type="button"
                onClick={onClose}
                disabled={isSubmitting}
                className="px-3 py-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors font-medium"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!title.trim() || isSubmitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-semibold shadow-xs"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={13} className="animate-spin" />
                    <span>Creating...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={13} />
                    <span>Create Incident</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
