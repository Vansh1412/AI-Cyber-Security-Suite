/**
 * frontend/src/pages/soc/IncidentManager.tsx
 * ───────────────────────────────────────────
 * Production SOC Incident Management Workspace.
 * Coordinated incident aggregation, investigation drawers, and status transitions.
 */

import React, { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertOctagon, RefreshCw } from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { incidentsService } from '@/services/soc/incidents'
import type { Incident } from '@/types/soc'
import {
  IncidentFilterState,
  IncidentFilterToolbar,
} from '@/components/soc/incidents/IncidentFilterToolbar'
import { IncidentTable } from '@/components/soc/incidents/IncidentTable'
import { IncidentDetailDrawer } from '@/components/soc/incidents/IncidentDetailDrawer'
import { IncidentStatusModal } from '@/components/soc/incidents/IncidentStatusModal'
import { AttachAlertModal } from '@/components/soc/incidents/AttachAlertModal'
import { CreateIncidentModal } from '@/components/soc/incidents/CreateIncidentModal'

export default function IncidentManager() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const currentUserId = user?.id
  const queryClient = useQueryClient()

  // ── URL Query Parameters Synchronization ────────────────────────────────────
  const [searchParams, setSearchParams] = useSearchParams()

  const page = useMemo(() => {
    const p = parseInt(searchParams.get('page') || '1', 10)
    return isNaN(p) || p < 1 ? 1 : p
  }, [searchParams])

  const size = useMemo(() => {
    const s = parseInt(searchParams.get('size') || '20', 10)
    return isNaN(s) || s < 1 ? 20 : s
  }, [searchParams])

  const filters: IncidentFilterState = useMemo(
    () => ({
      status: searchParams.get('status') || undefined,
      severity: searchParams.get('severity') || undefined,
    }),
    [searchParams]
  )

  const isFiltered = Boolean(filters.status || filters.severity)

  // ── Modal & Drawer States ───────────────────────────────────────────────────
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)

  const [statusModal, setStatusModal] = useState<{
    isOpen: boolean
    incident: Incident | null
  }>({
    isOpen: false,
    incident: null,
  })

  const [attachModal, setAttachModal] = useState<{
    isOpen: boolean
    incident: Incident | null
  }>({
    isOpen: false,
    incident: null,
  })

  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)

  // ── Data Query ──────────────────────────────────────────────────────────────
  const queryParams = useMemo(
    () => ({
      page,
      size,
      status: filters.status,
      severity: filters.severity,
    }),
    [page, size, filters]
  )

  const {
    data: incidents = [],
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['incidents', queryParams],
    queryFn: () => incidentsService.listIncidents(queryParams),
  })

  // ── Handlers ────────────────────────────────────────────────────────────────
  const handleFilterChange = useCallback(
    (newFilters: Partial<IncidentFilterState>) => {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('page', '1') // Reset to page 1 on filter modification

      const merged = { ...filters, ...newFilters }

      if (merged.status) nextParams.set('status', merged.status)
      else nextParams.delete('status')

      if (merged.severity) nextParams.set('severity', merged.severity)
      else nextParams.delete('severity')

      setSearchParams(nextParams)
    },
    [filters, searchParams, setSearchParams]
  )

  const handleResetFilters = useCallback(() => {
    const nextParams = new URLSearchParams()
    nextParams.set('page', '1')
    nextParams.set('size', String(size))
    setSearchParams(nextParams)
  }, [size, setSearchParams])

  const handlePageChange = useCallback(
    (newPage: number) => {
      const nextParams = new URLSearchParams(searchParams)
      nextParams.set('page', String(newPage))
      setSearchParams(nextParams)
    },
    [searchParams, setSearchParams]
  )

  // Drawer / Action Triggers
  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident)
    setIsDrawerOpen(true)
  }

  const handleCloseDrawer = () => {
    setIsDrawerOpen(false)
  }

  const handleOpenStatusModal = (incident: Incident) => {
    setStatusModal({ isOpen: true, incident })
  }

  const handleOpenAttachModal = (incident: Incident) => {
    setAttachModal({ isOpen: true, incident })
  }

  const handleMutationSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['incidents'] })
    if (selectedIncident) {
      queryClient.invalidateQueries({ queryKey: ['incident', selectedIncident.id] })
    }
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight flex items-center gap-2">
              <AlertOctagon className="text-primary-500 dark:text-primary-400" size={22} />
              <span>Incident Management</span>
            </h1>
            {isAdmin && (
              <span className="px-2 py-0.5 rounded-full text-3xs font-bold uppercase tracking-wider bg-primary-500/20 text-primary-600 dark:text-primary-300 border border-primary-500/30">
                Global Admin Scope
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Aggregated security cases, IOC correlations, and threat response tracking.
          </p>
        </div>

        <button
          type="button"
          onClick={() => refetch()}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-light-border dark:border-dark-border text-xs font-semibold text-gray-600 dark:text-gray-300 hover:bg-light-hover dark:hover:bg-dark-hover transition-colors shadow-2xs"
        >
          <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <IncidentFilterToolbar
        filters={filters}
        onFilterChange={handleFilterChange}
        onReset={handleResetFilters}
        onCreateClick={() => setIsCreateModalOpen(true)}
        isFiltered={isFiltered}
      />

      {/* Incident Paginated Table */}
      <IncidentTable
        incidents={incidents}
        isLoading={isLoading}
        page={page}
        pageSize={size}
        onPageChange={handlePageChange}
        onSelectIncident={handleSelectIncident}
        onStatusClick={handleOpenStatusModal}
        onAttachAlertClick={handleOpenAttachModal}
        currentUserId={currentUserId}
      />

      {/* Slide-out Diagnostic Drawer */}
      <IncidentDetailDrawer
        incident={selectedIncident}
        isOpen={isDrawerOpen}
        onClose={handleCloseDrawer}
        onStatusClick={handleOpenStatusModal}
        onAttachAlertClick={handleOpenAttachModal}
        onIncidentUpdated={handleMutationSuccess}
        currentUserId={currentUserId}
        isAdmin={isAdmin}
      />

      {/* Status Transition Modal */}
      <IncidentStatusModal
        incident={statusModal.incident}
        isOpen={statusModal.isOpen}
        onClose={() => setStatusModal({ isOpen: false, incident: null })}
        onSuccess={handleMutationSuccess}
      />

      {/* Attach Alerts Modal */}
      <AttachAlertModal
        incident={attachModal.incident}
        isOpen={attachModal.isOpen}
        onClose={() => setAttachModal({ isOpen: false, incident: null })}
        onSuccess={handleMutationSuccess}
      />

      {/* Create New Incident Modal */}
      <CreateIncidentModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onSuccess={handleMutationSuccess}
      />
    </div>
  )
}
