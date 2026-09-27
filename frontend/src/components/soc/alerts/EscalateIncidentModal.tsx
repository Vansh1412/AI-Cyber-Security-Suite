/**
 * frontend/src/components/soc/alerts/EscalateIncidentModal.tsx
 * ────────────────────────────────────────────────────────────
 * Escalation modal allowing analyst to either create a new Incident or attach the alert to an existing open Incident.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { AlertCircle, Flame, Link2, Loader2, Plus, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Alert, EventSeverity } from '@/types/soc'
import { incidentsService } from '@/services/soc/incidents'
import { clsx } from 'clsx'

export interface EscalateIncidentModalProps {
  alert: Alert | null
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

export function EscalateIncidentModal({
  alert,
  isOpen,
  onClose,
  onSuccess,
}: EscalateIncidentModalProps) {
  const [tab, setTab] = useState<'create' | 'link'>('create')

  // Form states for Create New Incident
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState<string>('HIGH')

  // Form state for Link Existing Incident
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Query existing active open incidents for tab 2
  const { data: openIncidents, isLoading: loadingIncidents } = useQuery({
    queryKey: ['incidents-active'],
    queryFn: () => incidentsService.listIncidents({ status: 'OPEN' }),
    enabled: isOpen && tab === 'link',
  })

  useEffect(() => {
    if (alert && isOpen) {
      setTitle(`[Security Alert] ${alert.rule_name}: ${alert.indicator_value}`)
      setDescription(
        `Escalated from Alert UUID: ${alert.alert_uuid}\nIndicator: ${alert.indicator_value} (${alert.indicator_type})\nDetection Rule: ${alert.rule_name}\nOccurrences: ${alert.occurrence_count}\nIngestion Timestamp: ${alert.first_seen_at}`
      )
      setSeverity(alert.severity || 'HIGH')
      setSelectedIncidentId(null)
      setIsSubmitting(false)
    }
  }, [alert, isOpen])

  if (!isOpen || !alert) return null

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!title.trim() || isSubmitting) return

    setIsSubmitting(true)
    try {
      await incidentsService.createIncident({
        title: title.trim(),
        description: description.trim() || undefined,
        severity: severity as EventSeverity,
        alert_ids: [alert.id],
      })
      toast.success('Incident successfully created and linked!')
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as { response?: { data?: { detail?: string } } }
      const msg = errorObj?.response?.data?.detail || 'Failed to create incident'
      toast.error(typeof msg === 'string' ? msg : 'Incident creation failed')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleLinkSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedIncidentId || isSubmitting) return

    setIsSubmitting(true)
    try {
      await incidentsService.attachAlerts(selectedIncidentId, {
        alert_ids: [alert.id],
      })
      toast.success(`Alert attached to Incident #${selectedIncidentId}`)
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as { response?: { data?: { detail?: string } } }
      const msg = errorObj?.response?.data?.detail || 'Failed to link alert to incident'
      toast.error(typeof msg === 'string' ? msg : 'Alert attachment failed')
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
          className="relative w-full max-w-lg bg-dark-card border border-dark-border rounded-2xl shadow-2xl p-6 z-10 space-y-5"
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-rose-500/15 flex items-center justify-center text-rose-400 shrink-0">
                <Flame size={20} />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Escalate Alert to Incident</h3>
                <p className="text-2xs text-gray-400 mt-0.5">
                  Promote this indicator into a coordinated security case.
                </p>
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

          {/* Mode Selector Tabs */}
          <div className="flex rounded-xl bg-dark-surface p-1 border border-dark-border text-xs">
            <button
              type="button"
              onClick={() => setTab('create')}
              className={clsx(
                'flex-1 py-1.5 px-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-1.5',
                tab === 'create'
                  ? 'bg-primary-600 text-white shadow-glow-primary'
                  : 'text-gray-400 hover:text-white'
              )}
            >
              <Plus size={13} />
              <span>Create New Incident</span>
            </button>
            <button
              type="button"
              onClick={() => setTab('link')}
              className={clsx(
                'flex-1 py-1.5 px-3 rounded-lg font-medium transition-colors flex items-center justify-center gap-1.5',
                tab === 'link'
                  ? 'bg-primary-600 text-white shadow-glow-primary'
                  : 'text-gray-400 hover:text-white'
              )}
            >
              <Link2 size={13} />
              <span>Link to Existing</span>
            </button>
          </div>

          {/* Tab 1: Create New Incident Form */}
          {tab === 'create' && (
            <form onSubmit={handleCreateSubmit} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                  Incident Title <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-white focus:outline-none focus:border-primary-500"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                    Incident Severity
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-white focus:outline-none focus:border-primary-500 cursor-pointer"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                    <option value="INFO">INFO</option>
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                    Linked Alert
                  </label>
                  <div className="px-3 py-2 bg-dark-surface/50 border border-dark-border rounded-xl text-xs text-gray-400 font-mono truncate">
                    Alert ID #{alert.id}
                  </div>
                </div>
              </div>

              <div className="space-y-1">
                <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                  Case Scope & Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 bg-dark-surface border border-dark-border rounded-xl text-xs text-white focus:outline-none focus:border-primary-500 resize-none font-mono"
                />
              </div>

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
                  disabled={!title.trim() || isSubmitting}
                  className="btn-primary text-xs py-2 px-4 disabled:opacity-40 disabled:pointer-events-none inline-flex items-center gap-1.5"
                >
                  {isSubmitting && <Loader2 size={13} className="animate-spin" />}
                  <span>Create & Escalate</span>
                </button>
              </div>
            </form>
          )}

          {/* Tab 2: Link to Existing Incident Form */}
          {tab === 'link' && (
            <form onSubmit={handleLinkSubmit} className="space-y-4 text-xs">
              <div className="space-y-2">
                <label className="block text-2xs font-semibold uppercase tracking-wider text-gray-300">
                  Select Target Open Incident <span className="text-rose-400">*</span>
                </label>

                {loadingIncidents ? (
                  <div className="p-4 rounded-xl bg-dark-surface border border-dark-border flex items-center justify-center gap-2 text-gray-400">
                    <Loader2 size={14} className="animate-spin text-primary-400" />
                    <span>Loading active cases...</span>
                  </div>
                ) : !openIncidents || openIncidents.length === 0 ? (
                  <div className="p-4 rounded-xl bg-dark-surface border border-dark-border text-center text-gray-500">
                    <AlertCircle size={20} className="mx-auto mb-1 opacity-60" />
                    <span>No active open incidents found. Please create a new incident.</span>
                  </div>
                ) : (
                  <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                    {openIncidents.map((inc) => (
                      <div
                        key={inc.id}
                        onClick={() => setSelectedIncidentId(inc.id)}
                        className={clsx(
                          'p-3 rounded-xl border text-xs cursor-pointer transition-colors flex items-center justify-between gap-2',
                          selectedIncidentId === inc.id
                            ? 'bg-primary-600/15 border-primary-500 text-white'
                            : 'bg-dark-surface border-dark-border text-gray-300 hover:bg-dark-hover'
                        )}
                      >
                        <div className="min-w-0">
                          <p className="font-semibold truncate">{inc.title}</p>
                          <p className="text-2xs text-gray-500 font-mono mt-0.5">
                            ID #{inc.id} • Severity: {inc.severity} • {inc.alert_count} alerts
                          </p>
                        </div>
                        <input
                          type="radio"
                          name="target_incident"
                          checked={selectedIncidentId === inc.id}
                          onChange={() => setSelectedIncidentId(inc.id)}
                          className="text-primary-500 focus:ring-0"
                        />
                      </div>
                    ))}
                  </div>
                )}
              </div>

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
                  disabled={!selectedIncidentId || isSubmitting}
                  className="btn-primary text-xs py-2 px-4 disabled:opacity-40 disabled:pointer-events-none inline-flex items-center gap-1.5"
                >
                  {isSubmitting && <Loader2 size={13} className="animate-spin" />}
                  <span>Attach to Incident</span>
                </button>
              </div>
            </form>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
