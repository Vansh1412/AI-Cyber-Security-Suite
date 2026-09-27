/**
 * frontend/src/pages/soc/AlertConsole.tsx
 * ───────────────────────────────────────
 * Production SOC Alert Console and Triage Lifecycle Workspace.
 */

import React, { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, RefreshCw, ShieldAlert } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { useAuth } from '@/contexts/AuthContext'
import { alertsService } from '@/services/soc/alerts'
import type { Alert } from '@/types/soc'
import { AlertDetailDrawer } from '@/components/soc/alerts/AlertDetailDrawer'
import { AlertFilterState, AlertFilterToolbar } from '@/components/soc/alerts/AlertFilterToolbar'
import { AlertStatsBar } from '@/components/soc/alerts/AlertStatsBar'
import { AlertTable } from '@/components/soc/alerts/AlertTable'
import { EscalateIncidentModal } from '@/components/soc/alerts/EscalateIncidentModal'
import { TriageActionModal, TriageActionType } from '@/components/soc/alerts/TriageActionModal'

export default function AlertConsole() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  // ── URL Query Parameters Synchronization ────────────────────────────────────
  const [searchParams, setSearchParams] = useSearchParams()

  const page = useMemo(() => {
    const p = parseInt(searchParams.get('page') || '1', 10)
    return isNaN(p) || p < 1 ? 1 : p
  }, [searchParams])

  const pageSize = useMemo(() => {
    const s = parseInt(searchParams.get('page_size') || '20', 10)
    return isNaN(s) || s < 1 ? 20 : s
  }, [searchParams])

  const filters: AlertFilterState = useMemo(
    () => ({
      status: searchParams.get('status') || undefined,
      severity: searchParams.get('severity') || undefined,
      indicator_type: searchParams.get('indicator_type') || undefined,
      search: searchParams.get('search') || undefined,
    }),
    [searchParams]
  )

  const isFiltered = Boolean(
    filters.status || filters.severity || filters.indicator_type || filters.search
  )

  // ── Modals & Drawer State ───────────────────────────────────────────────────
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)

  const [triageModal, setTriageModal] = useState<{
    isOpen: boolean
    actionType: TriageActionType | null
    alert: Alert | null
  }>({
    isOpen: false,
    actionType: null,
    alert: null,
  })

  const [escalateModal, setEscalateModal] = useState<{
    isOpen: boolean
    alert: Alert | null
  }>({
    isOpen: false,
    alert: null,
  })

  // ── Data Queries ────────────────────────────────────────────────────────────
  const queryFilterParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      severity: filters.severity,
      status: filters.status,
      indicator_type: filters.indicator_type,
      rule_name: filters.search,
    }),
    [page, pageSize, filters]
  )

  const {
    data: alertsData,
    isLoading: loadingAlerts,
    error: alertsError,
    refetch: refetchAlerts,
  } = useQuery({
    queryKey: ['alerts', queryFilterParams],
    queryFn: () => alertsService.listAlerts(queryFilterParams),
  })

  const {
    data: statsData,
    isLoading: loadingStats,
    error: statsError,
  } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => alertsService.getAlertStats(),
  })

  // ── URL Filter Update Handlers ──────────────────────────────────────────────
  const handleFilterChange = useCallback(
    (newFilters: Partial<AlertFilterState>) => {
      const nextParams = new URLSearchParams(searchParams)

      // Reset to page 1 whenever any filter changes
      nextParams.set('page', '1')

      const merged = { ...filters, ...newFilters }

      if (merged.status) nextParams.set('status', merged.status)
      else nextParams.delete('status')

      if (merged.severity) nextParams.set('severity', merged.severity)
      else nextParams.delete('severity')

      if (merged.indicator_type) nextParams.set('indicator_type', merged.indicator_type)
      else nextParams.delete('indicator_type')

      if (merged.search) nextParams.set('search', merged.search)
      else nextParams.delete('search')

      setSearchParams(nextParams)
    },
    [filters, searchParams, setSearchParams]
  )

  const handleResetFilters = useCallback(() => {
    const nextParams = new URLSearchParams()
    nextParams.set('page', '1')
    nextParams.set('page_size', String(pageSize))
    setSearchParams(nextParams)
  }, [pageSize, setSearchParams])

  const handlePageChange = useCallback(
    (newPage: number) => {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('page', String(newPage))
      setSearchParams(nextParams)
    },
    [searchParams, setSearchParams]
  )

  const handlePageSizeChange = useCallback(
    (newPageSize: number) => {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('page', '1')
      nextParams.set('page_size', String(newPageSize))
      setSearchParams(nextParams)
    },
    [searchParams, setSearchParams]
  )

  // ── Drawer Handlers ─────────────────────────────────────────────────────────
  const handleSelectAlert = (alert: Alert) => {
    setSelectedAlert(alert)
    setIsDrawerOpen(true)
  }

  const handleCloseDrawer = () => {
    setIsDrawerOpen(false)
  }

  // ── Triage Modal Action Triggers ────────────────────────────────────────────
  const openTriageAction = (alert: Alert, actionType: TriageActionType) => {
    setTriageModal({
      isOpen: true,
      actionType,
      alert,
    })
  }

  const openEscalateAction = (alert: Alert) => {
    setEscalateModal({
      isOpen: true,
      alert,
    })
  }

  // ── Mutation: Triage State Transitions ──────────────────────────────────────
  const triageMutation = useMutation({
    mutationFn: async ({
      alertUuid,
      actionType,
      payload,
    }: {
      alertUuid: string
      actionType: TriageActionType
      payload: {
        notes?: string
        resolution_notes?: string
        dismiss_reason?: string
        triage_notes?: string
        reopen_notes?: string
      }
    }) => {
      switch (actionType) {
        case 'acknowledge':
          return await alertsService.acknowledgeAlert(alertUuid, { notes: payload.notes })
        case 'resolve':
          return await alertsService.resolveAlert(alertUuid, {
            resolution_notes: payload.resolution_notes,
          })
        case 'dismiss':
          return await alertsService.dismissAlert(alertUuid, {
            dismiss_reason: payload.dismiss_reason!,
            triage_notes: payload.triage_notes,
          })
        case 'reopen':
          return await alertsService.reopenAlert(alertUuid, { reopen_notes: payload.reopen_notes })
      }
    },
    onSuccess: (updatedAlert, vars) => {
      toast.success(
        vars.actionType === 'acknowledge'
          ? 'Alert claimed for active triage.'
          : vars.actionType === 'resolve'
          ? 'Alert marked as resolved.'
          : vars.actionType === 'dismiss'
          ? 'Alert dismissed.'
          : 'Alert reopened back to triage pool.'
      )

      // Invalidate queries to refresh lists and metrics
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
      queryClient.invalidateQueries({ queryKey: ['alert-stats'] })

      // Update active drawer if it was inspecting this alert
      if (selectedAlert?.alert_uuid === updatedAlert.alert_uuid) {
        setSelectedAlert(updatedAlert)
      }

      setTriageModal({ isOpen: false, actionType: null, alert: null })
    },
    onError: (err: unknown) => {
      const errorObj = err as { response?: { status?: number; data?: { detail?: string } } }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 400) {
        toast.error(typeof msg === 'string' ? msg : 'Alert state has changed or this transition is not allowed.')
      } else if (status === 403) {
        toast.error('Permission denied: Action requires authorized privileges.')
      } else if (status === 404) {
        toast.error('Alert not found or access denied.')
      } else if (status === 409) {
        toast.error(typeof msg === 'string' ? msg : 'Conflict: Alert state was modified concurrently.')
      } else if (status === 422) {
        toast.error(typeof msg === 'string' ? msg : 'Validation error: Please verify mandatory fields.')
      } else if (status === 429) {
        toast.error('Too many requests. Please wait a moment before trying again.')
      } else {
        toast.error('Triage action failed. Please try again.')
      }
    },
  })

  const handleTriageSubmit = async (payload: {
    notes?: string
    resolution_notes?: string
    dismiss_reason?: string
    triage_notes?: string
    reopen_notes?: string
  }) => {
    if (!triageModal.alert || !triageModal.actionType) return
    await triageMutation.mutateAsync({
      alertUuid: triageModal.alert.alert_uuid,
      actionType: triageModal.actionType,
      payload,
    })
  }

  const handleEscalateSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
    queryClient.invalidateQueries({ queryKey: ['incidents-active'] })
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <ShieldAlert className="text-primary-400" size={22} />
              <span>Security Alerts & Triage</span>
            </h1>
            {isAdmin && (
              <span className="px-2 py-0.5 rounded-full text-3xs font-bold uppercase tracking-wider bg-primary-500/20 text-primary-300 border border-primary-500/30">
                Global Admin Scope
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Real-time threat detection, automated deduplication, and directed analyst triage workspace.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => {
              refetchAlerts()
              queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
              toast.success('Alerts refreshed', { duration: 1200 })
            }}
            className="btn-secondary py-2 px-3 text-xs inline-flex items-center gap-1.5"
            title="Refresh current alert queue"
          >
            <RefreshCw size={13} className={loadingAlerts ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Top Telemetry & KPI Stats Bar */}
      <AlertStatsBar
        stats={statsData}
        isLoading={loadingStats}
        error={statsError ? 'Failed to fetch telemetry' : null}
      />

      {/* Alert Ingestion Error Banner */}
      {alertsError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle size={16} className="text-rose-400 shrink-0" />
          <span>Failed to load security alerts. Please verify network connectivity or session credentials.</span>
        </div>
      )}

      {/* Filter and Search Controls Toolbar */}
      <AlertFilterToolbar
        filters={filters}
        onFilterChange={handleFilterChange}
        onResetFilters={handleResetFilters}
        isFiltered={isFiltered}
        totalItems={alertsData?.total}
      />

      {/* Main Alert Data Table */}
      <AlertTable
        alerts={alertsData?.items || []}
        total={alertsData?.total || 0}
        page={page}
        pageSize={pageSize}
        isLoading={loadingAlerts}
        selectedAlertUuid={selectedAlert?.alert_uuid}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        onSelectAlert={handleSelectAlert}
        onAcknowledge={(a) => openTriageAction(a, 'acknowledge')}
        onResolve={(a) => openTriageAction(a, 'resolve')}
        onDismiss={(a) => openTriageAction(a, 'dismiss')}
        onReopen={(a) => openTriageAction(a, 'reopen')}
        onEscalate={openEscalateAction}
        onResetFilters={isFiltered ? handleResetFilters : undefined}
        isAdmin={isAdmin}
      />

      {/* Slide-Over Diagnostics & Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isDrawerOpen}
        onClose={handleCloseDrawer}
        onAcknowledge={(a) => openTriageAction(a, 'acknowledge')}
        onResolve={(a) => openTriageAction(a, 'resolve')}
        onDismiss={(a) => openTriageAction(a, 'dismiss')}
        onReopen={(a) => openTriageAction(a, 'reopen')}
        onEscalate={openEscalateAction}
      />

      {/* Unified Triage Action Modal (Claim, Resolve, Dismiss, Reopen) */}
      <TriageActionModal
        alert={triageModal.alert}
        actionType={triageModal.actionType}
        isOpen={triageModal.isOpen}
        onClose={() => setTriageModal({ isOpen: false, actionType: null, alert: null })}
        onSubmit={handleTriageSubmit}
        isSubmitting={triageMutation.isPending}
      />

      {/* Escalate to Incident Modal */}
      <EscalateIncidentModal
        alert={escalateModal.alert}
        isOpen={escalateModal.isOpen}
        onClose={() => setEscalateModal({ isOpen: false, alert: null })}
        onSuccess={handleEscalateSuccess}
      />
    </div>
  )
}
