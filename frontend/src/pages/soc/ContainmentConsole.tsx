/**
 * frontend/src/pages/soc/ContainmentConsole.tsx
 * ─────────────────────────────────────────────
 * Primary SOC console for Threat Containment & SOAR Operations.
 * Integrates manual action invocation, rollback reversal, playbook audit, and policy controls.
 */

import React, { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { ShieldAlert } from 'lucide-react'
import type {
  ContainmentActionResponse,
  ContainmentPolicyUpdate,
  ContainmentRequest,
  PlaybookRunResponse,
} from '@/types/soc'
import { containmentService } from '@/services/soc/containment'
import { useSSEStream } from '@/hooks/useSSEStream'
import { LiveStreamIndicator } from '@/components/soc/LiveStreamIndicator'
import { ContainmentFilterToolbar } from '@/components/soc/containment/ContainmentFilterToolbar'
import { ContainmentActionTable } from '@/components/soc/containment/ContainmentActionTable'
import { ContainmentActionDrawer } from '@/components/soc/containment/ContainmentActionDrawer'
import { ManualContainmentModal } from '@/components/soc/containment/ManualContainmentModal'
import { RevertActionModal } from '@/components/soc/containment/RevertActionModal'
import { PlaybookRunsTable } from '@/components/soc/containment/PlaybookRunsTable'
import { PlaybookRunDrawer } from '@/components/soc/containment/PlaybookRunDrawer'
import { ContainmentPolicyCard } from '@/components/soc/containment/ContainmentPolicyCard'

type ActiveTab = 'actions' | 'playbooks' | 'policy'

export default function ContainmentConsole() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<ActiveTab>('actions')

  // SSE singleton hook connection
  const { status: sseStatus, lastEventId } = useSSEStream({ channel: 'soc' })

  // ── Actions View State ───────────────────────────────────────────────────────
  const [actionPage, setActionPage] = useState(1)
  const [actionTypeFilter, setActionTypeFilter] = useState('')
  const [actionStatusFilter, setActionStatusFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedAction, setSelectedAction] = useState<ContainmentActionResponse | null>(null)
  const [revertingAction, setRevertingAction] = useState<ContainmentActionResponse | null>(null)
  const [isExecuteModalOpen, setIsExecuteModalOpen] = useState(false)

  // ── Playbook Runs State ─────────────────────────────────────────────────────
  const [playbookPage, setPlaybookPage] = useState(1)
  const [selectedPlaybookRun, setSelectedPlaybookRun] = useState<PlaybookRunResponse | null>(null)

  // ── Query: Containment Actions ──────────────────────────────────────────────
  const {
    data: actionsData,
    isLoading: isLoadingActions,
    isFetching: isFetchingActions,
    refetch: refetchActions,
  } = useQuery({
    queryKey: [
      'containment-actions',
      { page: actionPage, action_type: actionTypeFilter, status: actionStatusFilter },
    ],
    queryFn: () =>
      containmentService.listActions({
        page: actionPage,
        page_size: 20,
        action_type: actionTypeFilter || undefined,
        status: actionStatusFilter || undefined,
      }),
  })

  // ── Query: Playbook Runs ────────────────────────────────────────────────────
  const {
    data: playbooksData,
    isLoading: isLoadingPlaybooks,
  } = useQuery({
    queryKey: ['playbook-runs', { page: playbookPage }],
    queryFn: () =>
      containmentService.listPlaybookRuns({
        page: playbookPage,
        page_size: 20,
      }),
    enabled: activeTab === 'playbooks',
  })

  // ── Query: Policy ───────────────────────────────────────────────────────────
  const {
    data: policyData,
    isLoading: isLoadingPolicy,
    refetch: refetchPolicy,
  } = useQuery({
    queryKey: ['containment-policy'],
    queryFn: () => containmentService.getPolicy(),
  })

  // ── Mutation: Execute Containment Action ────────────────────────────────────
  const executeMutation = useMutation({
    mutationFn: (payload: ContainmentRequest) => containmentService.containAction(payload),
    onSuccess: (newAction) => {
      queryClient.invalidateQueries({ queryKey: ['containment-actions'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-targets'] })
      if (newAction.status === 'BLOCKED_BY_ALLOWLIST') {
        toast(() => (
          <span className="flex items-center gap-2 text-xs">
            <ShieldAlert size={16} className="text-amber-400" />
            <span>Target is allowlisted. Rule 0 prevented containment.</span>
          </span>
        ))
      } else {
        toast.success(`Containment action ${newAction.action_type} executed.`)
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      toast.error(msg || 'Failed to execute containment action.')
    },
  })

  // ── Mutation: Revert Action ─────────────────────────────────────────────────
  const revertMutation = useMutation({
    mutationFn: (actionUuid: string) => containmentService.revertAction(actionUuid),
    onSuccess: (reverted) => {
      queryClient.invalidateQueries({ queryKey: ['containment-actions'] })
      queryClient.invalidateQueries({ queryKey: ['monitoring-targets'] })
      toast.success(`Action ${reverted.action_uuid.substring(0, 8)} reverted successfully.`)
      if (selectedAction?.action_uuid === reverted.action_uuid) {
        setSelectedAction(reverted)
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      toast.error(msg || 'Failed to rollback action.')
    },
  })

  // ── Mutation: Update Policy ─────────────────────────────────────────────────
  const policyMutation = useMutation({
    mutationFn: (payload: ContainmentPolicyUpdate) => containmentService.updatePolicy(payload),
    onSuccess: (updated) => {
      queryClient.setQueryData(['containment-policy'], updated)
      queryClient.invalidateQueries({ queryKey: ['containment-policy'] })
      toast.success(`Policy updated to v${updated.policy_version}.`)
    },
  })

  // Client-side search filtering on current page
  const filteredActions = useMemo(() => {
    if (!actionsData?.items) return []
    if (!searchQuery.trim()) return actionsData.items
    const q = searchQuery.toLowerCase()
    return actionsData.items.filter(
      (a) =>
        a.target_identifier.toLowerCase().includes(q) ||
        a.action_type.toLowerCase().includes(q) ||
        a.action_uuid.toLowerCase().includes(q)
    )
  }, [actionsData?.items, searchQuery])

  // Aggregate stats
  const totalActions = actionsData?.total || 0
  const executedCount =
    actionsData?.items.filter((a) => a.status === 'EXECUTED').length || 0
  const allowlistedCount =
    actionsData?.items.filter((a) => a.status === 'BLOCKED_BY_ALLOWLIST').length || 0
  const revertedCount =
    actionsData?.items.filter((a) => a.status === 'REVERTED').length || 0

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-in fade-in duration-150">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Threat Containment & SOAR
            </h1>
            <LiveStreamIndicator status={sseStatus} lastEventId={lastEventId} />
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Automated threat mitigation, Rule 0 allowlist fencing, and provenance-safe rollback workflows.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-gray-100 dark:bg-dark-bg p-1 rounded-xl border border-light-border dark:border-dark-border text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveTab('actions')}
            className={`px-3 py-1.5 rounded-lg transition-all ${
              activeTab === 'actions'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Actions & Audit
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('playbooks')}
            className={`px-3 py-1.5 rounded-lg transition-all ${
              activeTab === 'playbooks'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            SOAR Playbooks
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('policy')}
            className={`px-3 py-1.5 rounded-lg transition-all ${
              activeTab === 'policy'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            Policy Engine
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border shadow-xs">
          <span className="text-2xs font-semibold text-gray-500 uppercase">Total Actions</span>
          <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
            {totalActions}
          </p>
        </div>
        <div className="p-4 rounded-xl bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border shadow-xs">
          <span className="text-2xs font-semibold text-emerald-500 uppercase">Active Executed</span>
          <p className="text-2xl font-bold text-emerald-500 mt-1">{executedCount}</p>
        </div>
        <div className="p-4 rounded-xl bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border shadow-xs">
          <span className="text-2xs font-semibold text-amber-500 uppercase">Allowlist Fenced</span>
          <p className="text-2xl font-bold text-amber-500 mt-1">{allowlistedCount}</p>
        </div>
        <div className="p-4 rounded-xl bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border shadow-xs">
          <span className="text-2xs font-semibold text-purple-500 uppercase">Reverted Rollbacks</span>
          <p className="text-2xl font-bold text-purple-500 mt-1">{revertedCount}</p>
        </div>
      </div>

      {/* Tab 1: Actions View */}
      {activeTab === 'actions' && (
        <div className="space-y-4">
          <ContainmentFilterToolbar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            actionTypeFilter={actionTypeFilter}
            onActionTypeChange={(type) => {
              setActionTypeFilter(type)
              setActionPage(1)
            }}
            statusFilter={actionStatusFilter}
            onStatusChange={(status) => {
              setActionStatusFilter(status)
              setActionPage(1)
            }}
            onRefresh={() => refetchActions()}
            onOpenExecuteModal={() => setIsExecuteModalOpen(true)}
            isRefreshing={isFetchingActions}
          />

          <ContainmentActionTable
            actions={filteredActions}
            total={actionsData?.total || 0}
            page={actionPage}
            pageSize={20}
            onPageChange={setActionPage}
            isLoading={isLoadingActions}
            onSelectAction={setSelectedAction}
            onRevertAction={setRevertingAction}
            revertingActionUuid={revertMutation.isPending ? revertingAction?.action_uuid : null}
          />
        </div>
      )}

      {/* Tab 2: SOAR Playbooks View */}
      {activeTab === 'playbooks' && (
        <div className="space-y-4">
          <div className="p-4 bg-gray-50/70 dark:bg-dark-bg/50 border border-light-border dark:border-dark-border rounded-xl text-xs text-gray-500 flex items-center justify-between">
            <div>
              <span className="font-semibold text-gray-900 dark:text-white block">
                SOAR Playbook Execution Provenance
              </span>
              <span>
                Declarative typed action sequences triggered dynamically by qualifying alert evaluations.
              </span>
            </div>
            <span className="text-2xs font-mono font-medium px-2 py-0.5 rounded bg-gray-200 dark:bg-dark-border text-gray-700 dark:text-gray-300">
              Read-Only Audit Trail
            </span>
          </div>

          <PlaybookRunsTable
            runs={playbooksData?.items || []}
            total={playbooksData?.total || 0}
            page={playbookPage}
            pageSize={20}
            onPageChange={setPlaybookPage}
            isLoading={isLoadingPlaybooks}
            onSelectRun={setSelectedPlaybookRun}
          />
        </div>
      )}

      {/* Tab 3: Policy Engine View */}
      {activeTab === 'policy' && (
        <ContainmentPolicyCard
          policy={policyData || null}
          onUpdate={async (update) => {
            await policyMutation.mutateAsync(update)
          }}
          isUpdating={policyMutation.isPending}
          isLoading={isLoadingPolicy}
          onRefetch={() => refetchPolicy()}
        />
      )}

      {/* Drawers & Modals */}
      <ContainmentActionDrawer
        action={selectedAction}
        isOpen={!!selectedAction}
        onClose={() => setSelectedAction(null)}
        onRevert={(action) => setRevertingAction(action)}
        isReverting={revertMutation.isPending}
      />

      <PlaybookRunDrawer
        run={selectedPlaybookRun}
        isOpen={!!selectedPlaybookRun}
        onClose={() => setSelectedPlaybookRun(null)}
      />

      <ManualContainmentModal
        isOpen={isExecuteModalOpen}
        onClose={() => setIsExecuteModalOpen(false)}
        onSubmit={async (payload) => {
          await executeMutation.mutateAsync(payload)
        }}
        isPending={executeMutation.isPending}
      />

      <RevertActionModal
        isOpen={!!revertingAction}
        action={revertingAction}
        onClose={() => setRevertingAction(null)}
        onConfirm={async (actionUuid) => {
          await revertMutation.mutateAsync(actionUuid)
        }}
        isPending={revertMutation.isPending}
      />
    </div>
  )
}
