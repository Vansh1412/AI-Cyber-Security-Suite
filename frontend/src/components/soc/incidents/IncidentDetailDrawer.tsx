/**
 * frontend/src/components/soc/incidents/IncidentDetailDrawer.tsx
 * ──────────────────────────────────────────────────────────────
 * Slide-out diagnostic drawer displaying full Incident investigation overview,
 * aggregated IOC analytical context, and attached alerts management.
 */

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  Globe,
  Hash,
  Link2,
  Loader2,
  RefreshCw,
  Server,
  Shield,
  Trash2,
  User as UserIcon,
  UserCheck,
  UserMinus,
  X,
} from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { Incident } from '@/types/soc'
import { incidentsService } from '@/services/soc/incidents'
import { SeverityBadge } from '@/components/soc/alerts/SeverityBadge'
import { getIncidentStatusBadge } from './IncidentRow'
import { clsx } from 'clsx'

export interface IncidentDetailDrawerProps {
  incident: Incident | null
  isOpen: boolean
  onClose: () => void
  onStatusClick: (incident: Incident) => void
  onAttachAlertClick: (incident: Incident) => void
  onIncidentUpdated: () => void
  currentUserId?: number
  isAdmin?: boolean
}

export function IncidentDetailDrawer({
  incident,
  isOpen,
  onClose,
  onStatusClick,
  onAttachAlertClick,
  onIncidentUpdated,
  currentUserId,
  isAdmin,
}: IncidentDetailDrawerProps) {
  const [isAssigning, setIsAssigning] = useState(false)
  const [detachingAlertId, setDetachingAlertId] = useState<number | null>(null)

  // Query fresh incident details with full alerts and summary
  const { data: freshIncident, isLoading: loadingDetails } = useQuery({
    queryKey: ['incident', incident?.id],
    queryFn: () => (incident ? incidentsService.getIncident(incident.id) : null),
    enabled: isOpen && Boolean(incident),
  })

  const activeIncident = freshIncident || incident

  if (!isOpen || !activeIncident) return null

  const statusConfig = getIncidentStatusBadge(activeIncident.status)
  const isAssignedToCurrent =
    Boolean(currentUserId && activeIncident.assigned_to_user_id === currentUserId)

  // Extract analytical summary fields
  const summary = (activeIncident.summary || {}) as {
    alert_count?: number
    highest_severity?: string
    first_seen_at?: string
    last_seen_at?: string
    affected_indicators?: string[]
    affected_domains?: string[]
    affected_ips?: string[]
  }

  const indicators = summary.affected_indicators || []
  const domains = summary.affected_domains || []
  const ips = summary.affected_ips || []
  const attachedAlerts = activeIncident.alerts || []

  // Assign to Me / Unassign handlers
  const handleAssignToMe = async () => {
    if (!currentUserId || isAssigning) return
    setIsAssigning(true)
    try {
      await incidentsService.updateIncident(activeIncident.id, {
        assigned_to_user_id: currentUserId,
      })
      toast.success('Incident assigned to you.')
      onIncidentUpdated()
    } catch {
      toast.error('Failed to assign incident.')
    } finally {
      setIsAssigning(false)
    }
  }

  const handleUnassign = async () => {
    if (isAssigning) return
    setIsAssigning(true)
    try {
      await incidentsService.updateIncident(activeIncident.id, {
        assigned_to_user_id: null,
      })
      toast.success('Incident unassigned.')
      onIncidentUpdated()
    } catch {
      toast.error('Failed to unassign incident.')
    } finally {
      setIsAssigning(false)
    }
  }

  // Detach alert handler
  const handleDetachAlert = async (alertId: number) => {
    setDetachingAlertId(alertId)
    try {
      await incidentsService.detachAlert(activeIncident.id, alertId)
      toast.success('Alert detached from incident.')
      onIncidentUpdated()
    } catch {
      toast.error('Failed to detach alert.')
    } finally {
      setDetachingAlertId(null)
    }
  }

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      return new Date(dateStr).toLocaleString()
    } catch {
      return dateStr
    }
  }

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
          className="relative w-full max-w-2xl h-full bg-white dark:bg-dark-card border-l border-light-border dark:border-dark-border shadow-2xl z-10 flex flex-col overflow-hidden"
        >
          {/* Header */}
          <div className="p-6 border-b border-light-border dark:border-dark-border/80 flex items-start justify-between gap-4 bg-light-surface/40 dark:bg-dark-surface/40">
            <div className="space-y-1.5 flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={activeIncident.severity} />
                <span
                  className={clsx(
                    'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border select-none',
                    statusConfig.classes
                  )}
                >
                  <span className={clsx('h-1.5 w-1.5 rounded-full', statusConfig.dot)} />
                  <span>{statusConfig.label}</span>
                </span>
                <span className="text-3xs font-mono text-gray-400">
                  UUID: {activeIncident.incident_uuid}
                </span>
                {loadingDetails && (
                  <RefreshCw size={12} className="animate-spin text-primary-400" />
                )}
              </div>
              <h2 className="text-base font-bold text-gray-900 dark:text-white truncate">
                {activeIncident.title}
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
            {/* Overview & Description */}
            <div className="space-y-2">
              <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider">
                Case Overview
              </h3>
              <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-surface/50 border border-light-border dark:border-dark-border space-y-3">
                <p className="text-gray-700 dark:text-gray-200 leading-relaxed whitespace-pre-wrap">
                  {activeIncident.description || 'No description provided.'}
                </p>

                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 pt-3 border-t border-light-border dark:border-dark-border/60 text-2xs">
                  <div>
                    <span className="text-gray-500 block">Created:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium">
                      {formatDate(activeIncident.created_at)}
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-500 block">Last Updated:</span>
                    <span className="text-gray-800 dark:text-gray-200 font-medium">
                      {formatDate(activeIncident.updated_at)}
                    </span>
                  </div>
                  {activeIncident.closed_at && (
                    <div>
                      <span className="text-gray-500 block">Closed At:</span>
                      <span className="text-gray-800 dark:text-gray-200 font-medium">
                        {formatDate(activeIncident.closed_at)}
                      </span>
                    </div>
                  )}
                </div>

                {/* Resolution Notes */}
                {activeIncident.resolution_notes && (
                  <div className="pt-3 border-t border-light-border dark:border-dark-border/60">
                    <span className="text-gray-500 block text-2xs font-bold uppercase tracking-wider mb-1">
                      Resolution Notes:
                    </span>
                    <p className="text-gray-700 dark:text-gray-300 italic bg-light-surface/60 dark:bg-dark-card p-2.5 rounded-lg border border-light-border dark:border-dark-border">
                      {activeIncident.resolution_notes}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Analyst Ownership & Assignment */}
            <div className="space-y-2">
              <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider">
                Analyst Assignment
              </h3>
              <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-surface/50 border border-light-border dark:border-dark-border flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <UserIcon size={16} className="text-gray-400" />
                  <div>
                    <span className="text-2xs text-gray-500 block">Current Assignee:</span>
                    <span className="font-semibold text-gray-900 dark:text-gray-100">
                      {activeIncident.assigned_to_user_id
                        ? isAssignedToCurrent
                          ? 'Assigned to You'
                          : `Analyst ID #${activeIncident.assigned_to_user_id}`
                        : 'Unassigned'}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {!isAssignedToCurrent ? (
                    <button
                      type="button"
                      onClick={handleAssignToMe}
                      disabled={isAssigning}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-50 transition-colors shadow-xs"
                    >
                      <UserCheck size={14} />
                      <span>Assign to Me</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={handleUnassign}
                      disabled={isAssigning}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-700 dark:text-gray-300 border border-light-border dark:border-dark-border hover:bg-light-hover dark:hover:bg-dark-hover disabled:opacity-50 transition-colors"
                    >
                      <UserMinus size={14} />
                      <span>Unassign</span>
                    </button>
                  )}
                  {isAdmin && !isAssignedToCurrent && Boolean(activeIncident.assigned_to_user_id) && (
                    <button
                      type="button"
                      onClick={handleUnassign}
                      disabled={isAssigning}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/20 hover:bg-rose-500/20 disabled:opacity-50 transition-colors"
                      title="Admin Override: Unassign analyst"
                    >
                      <UserMinus size={14} />
                      <span>Admin Unassign</span>
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Aggregated Analytical Context */}
            <div className="space-y-2">
              <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider">
                Analytical Summary Context
              </h3>
              <div className="p-4 rounded-xl bg-light-hover/40 dark:bg-dark-surface/50 border border-light-border dark:border-dark-border space-y-3">
                {/* Domains */}
                <div>
                  <span className="text-3xs text-gray-400 uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                    <Globe size={11} />
                    <span>Affected Domains ({domains.length}):</span>
                  </span>
                  {domains.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {domains.map((dom) => (
                        <span
                          key={dom}
                          className="px-2 py-0.5 rounded-md bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border text-3xs font-mono text-gray-700 dark:text-gray-300"
                        >
                          {dom}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-3xs text-gray-500 italic">None derived</span>
                  )}
                </div>

                {/* IPs */}
                <div>
                  <span className="text-3xs text-gray-400 uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                    <Server size={11} />
                    <span>Affected IPs ({ips.length}):</span>
                  </span>
                  {ips.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {ips.map((ip) => (
                        <span
                          key={ip}
                          className="px-2 py-0.5 rounded-md bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border text-3xs font-mono text-gray-700 dark:text-gray-300"
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-3xs text-gray-500 italic">None derived</span>
                  )}
                </div>

                {/* Indicators */}
                <div>
                  <span className="text-3xs text-gray-400 uppercase tracking-wider font-bold block mb-1 flex items-center gap-1">
                    <Hash size={11} />
                    <span>Raw Indicators ({indicators.length}):</span>
                  </span>
                  {indicators.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                      {indicators.map((ind) => (
                        <span
                          key={ind}
                          className="px-2 py-0.5 rounded-md bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border text-3xs font-mono text-primary-400 truncate max-w-xs"
                          title={ind}
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-3xs text-gray-500 italic">None derived</span>
                  )}
                </div>
              </div>
            </div>

            {/* Attached Alerts Section */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-2xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Shield size={13} className="text-primary-400" />
                  <span>Attached Security Alerts ({attachedAlerts.length})</span>
                </h3>
                <button
                  type="button"
                  onClick={() => onAttachAlertClick(activeIncident)}
                  className="flex items-center gap-1 text-2xs text-primary-400 hover:text-primary-300 font-semibold"
                >
                  <Link2 size={12} />
                  <span>Attach Alerts</span>
                </button>
              </div>

              {attachedAlerts.length === 0 ? (
                <div className="p-6 text-center text-gray-500 border border-dashed border-light-border dark:border-dark-border rounded-xl">
                  No alerts currently attached to this incident.
                </div>
              ) : (
                <div className="divide-y divide-light-border dark:divide-dark-border/40 border border-light-border dark:border-dark-border rounded-xl overflow-hidden bg-light-surface/30 dark:bg-dark-surface/30">
                  {attachedAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-3 flex items-center justify-between gap-3 hover:bg-light-hover/40 dark:hover:bg-dark-hover/40 transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <SeverityBadge severity={alert.severity} />
                        <div className="min-w-0">
                          <p className="text-2xs font-semibold text-gray-900 dark:text-gray-100 truncate">
                            {alert.rule_name}: {alert.indicator_value}
                          </p>
                          <p className="text-3xs text-gray-400 font-mono">
                            Alert #{alert.alert_uuid.slice(0, 8)} • Seen: {alert.occurrence_count}x
                          </p>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleDetachAlert(alert.id)}
                        disabled={detachingAlertId === alert.id}
                        className="p-1.5 text-gray-400 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors shrink-0"
                        title="Detach Alert from Incident"
                      >
                        {detachingAlertId === alert.id ? (
                          <Loader2 size={13} className="animate-spin text-rose-400" />
                        ) : (
                          <Trash2 size={13} />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Drawer Actions Footer */}
          <div className="p-4 border-t border-light-border dark:border-dark-border/80 bg-light-surface/40 dark:bg-dark-surface/40 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={() => onStatusClick(activeIncident)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-amber-300 bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 transition-colors shadow-xs"
            >
              <RefreshCw size={14} />
              <span>Transition Status</span>
            </button>

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
