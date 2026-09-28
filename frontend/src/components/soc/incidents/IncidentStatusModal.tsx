/**
 * frontend/src/components/soc/incidents/IncidentStatusModal.tsx
 * ──────────────────────────────────────────────────────────────
 * Modal for controlled Incident Status transitions.
 * Enforces backend INCIDENT_STATUS_TRANSITIONS state machine rules client-side
 * and collects mandatory resolution notes for RESOLVED/CLOSED states.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, Loader2, RefreshCw, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Incident, IncidentStatus } from '@/types/soc'
import { incidentsService } from '@/services/soc/incidents'

export interface IncidentStatusModalProps {
  incident: Incident | null
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

// Authoritative state machine mapping matching backend INCIDENT_STATUS_TRANSITIONS
export const ALLOWED_STATUS_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  OPEN: ['INVESTIGATING', 'CLOSED'],
  INVESTIGATING: ['CONTAINED', 'OPEN', 'RESOLVED', 'CLOSED'],
  CONTAINED: ['INVESTIGATING', 'RESOLVED', 'CLOSED'],
  RESOLVED: ['CLOSED', 'OPEN'],
  CLOSED: ['OPEN'],
}

const ALL_STATUSES: IncidentStatus[] = [
  'OPEN',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'CLOSED',
]

export function IncidentStatusModal({
  incident,
  isOpen,
  onClose,
  onSuccess,
}: IncidentStatusModalProps) {
  const [selectedStatus, setSelectedStatus] = useState<IncidentStatus | ''>('')
  const [resolutionNotes, setResolutionNotes] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const currentStatus = (incident?.status || 'OPEN') as IncidentStatus
  const allowedTransitions = ALLOWED_STATUS_TRANSITIONS[currentStatus] || []

  useEffect(() => {
    if (incident && isOpen) {
      setSelectedStatus('')
      setResolutionNotes(incident.resolution_notes || '')
      setIsSubmitting(false)
    }
  }, [incident, isOpen])

  if (!isOpen || !incident) return null

  const isClosingState =
    selectedStatus === 'RESOLVED' || selectedStatus === 'CLOSED'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedStatus || isSubmitting) return

    if (isClosingState && !resolutionNotes.trim()) {
      toast.error('Resolution notes are required when resolving or closing an incident.')
      return
    }

    setIsSubmitting(true)
    try {
      await incidentsService.updateIncident(incident.id, {
        status: selectedStatus,
        resolution_notes: resolutionNotes.trim() || undefined,
      })
      toast.success(`Incident status transitioned to ${selectedStatus}`)
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 400) {
        toast.error(typeof msg === 'string' ? msg : 'Invalid status transition.')
      } else if (status === 403) {
        toast.error('Permission denied: You do not have permission to transition this incident.')
      } else if (status === 404) {
        toast.error('Incident not found or access denied.')
      } else if (status === 409) {
        toast.error('Conflict: Incident was modified concurrently by another analyst.')
      } else if (status === 422) {
        toast.error(typeof msg === 'string' ? msg : 'Validation error in transition payload.')
      } else {
        toast.error('Failed to update incident status. Please try again.')
      }
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

        {/* Modal Card */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="relative w-full max-w-md bg-white dark:bg-dark-card border border-light-border dark:border-dark-border rounded-2xl shadow-2xl p-6 z-10 space-y-4"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-amber-500/15 flex items-center justify-center text-amber-400 shrink-0">
                <RefreshCw size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white">
                  Transition Incident Status
                </h3>
                <p className="text-2xs text-gray-500 mt-0.5">
                  Update lifecycle state for #{incident.incident_uuid?.slice(0, 8) || incident.id}
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
            {/* Current State Info */}
            <div className="p-3 rounded-lg bg-light-hover dark:bg-dark-surface border border-light-border dark:border-dark-border flex items-center justify-between">
              <span className="text-gray-500 font-medium">Current Status:</span>
              <span className="font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                {currentStatus}
              </span>
            </div>

            {/* Target Status Selection */}
            <div className="space-y-1.5">
              <label htmlFor="target-status-select" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                New Target Status <span className="text-rose-400">*</span>
              </label>
              <select
                id="target-status-select"
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value as IncidentStatus)}
                required
                className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl px-3 py-2.5 focus:outline-hidden focus:border-primary-500 transition-colors"
              >
                <option value="" disabled>
                  Select target status...
                </option>
                {ALL_STATUSES.map((status) => {
                  const isAllowed = allowedTransitions.includes(status)
                  const isCurrent = status === currentStatus
                  return (
                    <option
                      key={status}
                      value={status}
                      disabled={!isAllowed || isCurrent}
                    >
                      {status} {isCurrent ? '(Current)' : !isAllowed ? '(Not Allowed)' : ''}
                    </option>
                  )
                })}
              </select>
              <p className="text-3xs text-gray-500">
                Permitted from {currentStatus}: {allowedTransitions.join(', ') || 'None'}
              </p>
            </div>

            {/* Resolution Notes (Prompted on RESOLVED or CLOSED) */}
            {isClosingState && (
              <div className="space-y-1.5 animate-fadeIn">
                <label htmlFor="resolution-notes-input" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                  Resolution Notes <span className="text-rose-400">*</span>
                </label>
                <textarea
                  id="resolution-notes-input"
                  rows={3}
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  placeholder="Detail root cause, containment actions, and resolution steps..."
                  required
                  className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl p-3 focus:outline-hidden focus:border-primary-500 transition-colors resize-none"
                />
              </div>
            )}

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
                disabled={!selectedStatus || isSubmitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-semibold shadow-xs"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={13} className="animate-spin" />
                    <span>Updating...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={13} />
                    <span>Apply Transition</span>
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
