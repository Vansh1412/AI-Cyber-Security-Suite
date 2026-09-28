/**
 * frontend/src/components/soc/incidents/AttachAlertModal.tsx
 * ──────────────────────────────────────────────────────────
 * Modal for attaching existing open alerts to a Security Incident.
 * Handles HTTP 409 Conflict gracefully if an alert was concurrently claimed.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  CheckCircle2,
  Link2,
  Loader2,
  X,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Alert, Incident } from '@/types/soc'
import { alertsService } from '@/services/soc/alerts'
import { incidentsService } from '@/services/soc/incidents'
import { SeverityBadge } from '@/components/soc/alerts/SeverityBadge'
import { clsx } from 'clsx'

export interface AttachAlertModalProps {
  incident: Incident | null
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

export function AttachAlertModal({
  incident,
  isOpen,
  onClose,
  onSuccess,
}: AttachAlertModalProps) {
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([])
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Query open alerts
  const { data: alertsData, isLoading: loadingAlerts } = useQuery({
    queryKey: ['alerts-unattached'],
    queryFn: () => alertsService.listAlerts({ status: 'OPEN', page: 1, page_size: 50 }),
    enabled: isOpen && Boolean(incident),
  })

  // Filter out alerts already attached to THIS incident
  const availableAlerts: Alert[] = React.useMemo(() => {
    if (!alertsData?.items || !incident) return []
    const alreadyAttachedIds = new Set(
      (incident.alerts || []).map((a) => a.id)
    )
    return alertsData.items.filter(
      (a) => !alreadyAttachedIds.has(a.id) && (!a.incident_id || a.incident_id !== incident.id)
    )
  }, [alertsData, incident])

  useEffect(() => {
    if (isOpen) {
      setSelectedAlertIds([])
      setIsSubmitting(false)
    }
  }, [isOpen])

  if (!isOpen || !incident) return null

  const handleToggleAlert = (alertId: number) => {
    setSelectedAlertIds((prev) =>
      prev.includes(alertId) ? prev.filter((id) => id !== alertId) : [...prev, alertId]
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (selectedAlertIds.length === 0 || isSubmitting) return

    setIsSubmitting(true)
    try {
      await incidentsService.attachAlerts(incident.id, {
        alert_ids: selectedAlertIds,
      })
      toast.success(`Attached ${selectedAlertIds.length} alert(s) to incident.`)
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 409) {
        toast.error(
          typeof msg === 'string'
            ? msg
            : 'Conflict: One or more selected alerts are already attached to another incident.'
        )
      } else if (status === 403) {
        toast.error('Permission denied: You do not own one or more of these alerts.')
      } else if (status === 404) {
        toast.error('Incident or alert not found.')
      } else {
        toast.error('Failed to attach alerts. Please try again.')
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
                <Link2 size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white">
                  Attach Alerts to Incident
                </h3>
                <p className="text-2xs text-gray-500 mt-0.5">
                  Link related threat indicators to incident #{incident.incident_uuid?.slice(0, 8) || incident.id}
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
            {/* List of Available Alerts */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-2xs text-gray-500">
                <span>Select open alerts to associate:</span>
                <span>{selectedAlertIds.length} selected</span>
              </div>

              <div className="max-h-60 overflow-y-auto divide-y divide-light-border dark:divide-dark-border/40 border border-light-border dark:border-dark-border rounded-xl bg-light-surface/40 dark:bg-dark-surface/40 p-1">
                {loadingAlerts ? (
                  <div className="p-6 text-center text-gray-500 flex items-center justify-center gap-2">
                    <Loader2 size={16} className="animate-spin text-primary-500" />
                    <span>Loading available alerts...</span>
                  </div>
                ) : availableAlerts.length === 0 ? (
                  <div className="p-6 text-center text-gray-500">
                    No unlinked open alerts currently available.
                  </div>
                ) : (
                  availableAlerts.map((alert) => {
                    const isSelected = selectedAlertIds.includes(alert.id)
                    return (
                      <div
                        key={alert.id}
                        onClick={() => handleToggleAlert(alert.id)}
                        className={clsx(
                          'flex items-center gap-3 p-2.5 rounded-lg cursor-pointer transition-colors',
                          isSelected
                            ? 'bg-primary-500/10 dark:bg-primary-500/15'
                            : 'hover:bg-light-hover dark:hover:bg-dark-hover/50'
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleAlert(alert.id)}
                          aria-label={`Select alert ${alert.rule_name}`}
                          className="rounded text-primary-600 focus:ring-primary-500"
                        />
                        <SeverityBadge severity={alert.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-2xs font-semibold text-gray-900 dark:text-gray-100 truncate">
                            {alert.rule_name}: {alert.indicator_value}
                          </p>
                          <p className="text-3xs text-gray-400 font-mono">
                            #{alert.alert_uuid.slice(0, 8)} • {alert.occurrence_count} occurrence(s)
                          </p>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>

            {/* Note on Monotonic Severity */}
            <p className="text-3xs text-gray-400 italic">
              Note: Attaching an alert with higher severity will automatically escalate the incident's severity level.
            </p>

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
                disabled={selectedAlertIds.length === 0 || isSubmitting}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-semibold shadow-xs"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={13} className="animate-spin" />
                    <span>Attaching...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={13} />
                    <span>Attach Selected</span>
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
