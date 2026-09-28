/**
 * frontend/src/pages/soc/MonitoringConsole.tsx
 * ─────────────────────────────────────────────
 * Production SOC Continuous Target Monitoring Console.
 * Fleet surveillance, autonomous scheduled probes, on-demand execution, and diagnostics.
 */

import React, { useCallback, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Radio } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { useAuth } from '@/contexts/AuthContext'
import { monitoringService } from '@/services/soc/monitoring'
import type { MonitoringTarget } from '@/types/soc'
import { MonitoringStatsBar } from '@/components/soc/monitoring/MonitoringStatsBar'
import { TargetFilterToolbar } from '@/components/soc/monitoring/TargetFilterToolbar'
import { TargetTable } from '@/components/soc/monitoring/TargetTable'
import { TargetDetailDrawer } from '@/components/soc/monitoring/TargetDetailDrawer'
import { RegisterTargetModal } from '@/components/soc/monitoring/RegisterTargetModal'

export default function MonitoringConsole() {
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

  const includeInactive = useMemo(
    () => searchParams.get('include_inactive') === 'true',
    [searchParams]
  )

  // ── Modals & Drawer State ───────────────────────────────────────────────────
  const [selectedTarget, setSelectedTarget] = useState<MonitoringTarget | null>(null)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false)
  const [checkingTargetUuid, setCheckingTargetUuid] = useState<string | null>(null)

  // ── Data Queries ────────────────────────────────────────────────────────────
  const listQueryParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      include_inactive: includeInactive,
    }),
    [page, pageSize, includeInactive]
  )

  const {
    data: targetListData,
    isLoading: loadingTargets,
    refetch: refetchTargets,
    isRefetching,
  } = useQuery({
    queryKey: ['monitoring-targets', listQueryParams],
    queryFn: () => monitoringService.listTargets(listQueryParams),
  })

  const { data: statsData, isLoading: loadingStats } = useQuery({
    queryKey: ['monitoring-stats'],
    queryFn: () => monitoringService.getMonitoringStats(),
  })

  // ── Invalidation Helper ─────────────────────────────────────────────────────
  const invalidateTargetQueries = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['monitoring-targets'] })
    queryClient.invalidateQueries({ queryKey: ['monitoring-stats'] })
    if (selectedTarget) {
      queryClient.invalidateQueries({
        queryKey: ['monitoring-diagnostics', selectedTarget.target_uuid],
      })
    }
  }, [queryClient, selectedTarget])

  // ── Lifecycle Mutations ─────────────────────────────────────────────────────
  const checkNowMutation = useMutation({
    mutationFn: (uuid: string) => monitoringService.checkNow(uuid),
    onSuccess: (data) => {
      toast.success(data.message || 'Immediate probe dispatched to worker pool.')
      invalidateTargetQueries()
    },
    onError: (err: unknown) => {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 409) {
        toast.error(
          typeof msg === 'string'
            ? msg
            : 'Execution conflict: Target check already in progress or target suspended.'
        )
      } else if (status === 422) {
        toast.error('Target is paused. Please resume target before requesting check-now.')
      } else {
        toast.error('Failed to trigger immediate check.')
      }
    },
    onSettled: () => {
      setCheckingTargetUuid(null)
    },
  })

  const pauseResumeMutation = useMutation({
    mutationFn: ({ uuid, isCurrentlyActive }: { uuid: string; isCurrentlyActive: boolean }) =>
      isCurrentlyActive
        ? monitoringService.pauseTarget(uuid)
        : monitoringService.resumeTarget(uuid),
    onSuccess: (_, variables) => {
      toast.success(
        variables.isCurrentlyActive ? 'Target paused.' : 'Target resumed.'
      )
      invalidateTargetQueries()
    },
    onError: (err: unknown) => {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 409) {
        toast.error(
          typeof msg === 'string'
            ? msg
            : 'Target is auto-suspended due to excessive failures; use Reactivate.'
        )
      } else {
        toast.error('Failed to update target activation state.')
      }
    },
  })

  const reactivateMutation = useMutation({
    mutationFn: (uuid: string) => monitoringService.reactivateTarget(uuid),
    onSuccess: () => {
      toast.success('Target reactivated; failures reset to 0.')
      invalidateTargetQueries()
    },
    onError: () => {
      toast.error('Failed to reactivate target.')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (uuid: string) => monitoringService.deleteTarget(uuid),
    onSuccess: () => {
      toast.success('Monitoring target deactivated.')
      invalidateTargetQueries()
      if (selectedTarget) {
        setIsDrawerOpen(false)
        setSelectedTarget(null)
      }
    },
    onError: () => {
      toast.error('Failed to deactivate target.')
    },
  })

  // ── Action Handlers ─────────────────────────────────────────────────────────
  const handleCheckNow = (target: MonitoringTarget) => {
    setCheckingTargetUuid(target.target_uuid)
    checkNowMutation.mutate(target.target_uuid)
  }

  const handleTogglePauseResume = (target: MonitoringTarget) => {
    pauseResumeMutation.mutate({
      uuid: target.target_uuid,
      isCurrentlyActive: target.is_active,
    })
  }

  const handleReactivate = (target: MonitoringTarget) => {
    reactivateMutation.mutate(target.target_uuid)
  }

  const handleDelete = (target: MonitoringTarget) => {
    const confirmed = window.confirm(
      `Are you sure you want to deactivate surveillance for "${target.normalized_domain || target.url}"? The target will be soft-deleted and removed from active scheduling.`
    )
    if (confirmed) {
      deleteMutation.mutate(target.target_uuid)
    }
  }

  const handleSelectTarget = (target: MonitoringTarget) => {
    setSelectedTarget(target)
    setIsDrawerOpen(true)
  }

  const handleCloseDrawer = () => {
    setIsDrawerOpen(false)
  }

  // ── URL Filter Updates ──────────────────────────────────────────────────────
  const handleToggleIncludeInactive = (val: boolean) => {
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('page', '1')
    if (val) nextParams.set('include_inactive', 'true')
    else nextParams.delete('include_inactive')
    setSearchParams(nextParams)
  }

  const handlePageChange = (newPage: number) => {
    const nextParams = new URLSearchParams(searchParams)
    nextParams.set('page', String(newPage))
    setSearchParams(nextParams)
  }

  const quota = isAdmin ? 500 : 20
  const activeCount = statsData?.active_targets || 0

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight flex items-center gap-2">
              <Radio className="text-primary-500 dark:text-primary-400" size={22} />
              <span>Continuous Target Monitoring</span>
            </h1>
            <span className="px-2 py-0.5 rounded-full text-3xs font-bold font-mono uppercase tracking-wider bg-light-card dark:bg-dark-card border border-light-border dark:border-dark-border text-gray-700 dark:text-gray-300">
              Quota: {activeCount} / {quota} Active
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Autonomous threat probe fleet, distributed execution leases, and diagnostic health telemetry.
          </p>
        </div>
      </div>

      {/* Fleet KPI Statistics Bar */}
      <MonitoringStatsBar
        stats={statsData}
        isLoading={loadingStats}
        userRole={user?.role}
      />

      {/* Filter & Action Toolbar */}
      <TargetFilterToolbar
        includeInactive={includeInactive}
        onToggleIncludeInactive={handleToggleIncludeInactive}
        onRefresh={() => refetchTargets()}
        onAddTargetClick={() => setIsRegisterModalOpen(true)}
        isRefreshing={isRefetching}
      />

      {/* Target Inventory Table */}
      <TargetTable
        targets={targetListData?.items || []}
        total={targetListData?.total || 0}
        page={page}
        pageSize={pageSize}
        hasMore={Boolean(
          (targetListData as unknown as { has_more?: boolean })?.has_more ??
            (targetListData ? page * pageSize < targetListData.total : false)
        )}
        isLoading={loadingTargets}
        onPageChange={handlePageChange}
        onSelectTarget={handleSelectTarget}
        onCheckNow={handleCheckNow}
        onTogglePauseResume={handleTogglePauseResume}
        onReactivate={handleReactivate}
        onDelete={handleDelete}
        checkingTargetUuid={checkingTargetUuid}
      />

      {/* Diagnostic Telemetry Drawer */}
      <TargetDetailDrawer
        target={selectedTarget}
        isOpen={isDrawerOpen}
        onClose={handleCloseDrawer}
        onCheckNow={handleCheckNow}
        onTogglePauseResume={handleTogglePauseResume}
        onReactivate={handleReactivate}
        isCheckingNow={checkingTargetUuid === selectedTarget?.target_uuid}
      />

      {/* Add Target Registration Modal */}
      <RegisterTargetModal
        isOpen={isRegisterModalOpen}
        onClose={() => setIsRegisterModalOpen(false)}
        onSuccess={invalidateTargetQueries}
        currentActiveCount={activeCount}
        quotaLimit={quota}
      />
    </div>
  )
}
