/**
 * frontend/src/services/soc/containment.ts
 * ────────────────────────────────────────
 * Typed API client for Automated Threat Containment & SOAR Playbooks.
 */

import api from '@/services/api'
import type {
  ContainmentActionResponse,
  ContainmentPolicyResponse,
  ContainmentPolicyUpdate,
  ContainmentRequest,
  PaginatedContainmentActions,
  PaginatedPlaybookRuns,
} from '@/types/soc'

export interface ListActionsParams {
  page?: number
  page_size?: number
  action_type?: string
  status?: string
}

export interface ListPlaybookRunsParams {
  page?: number
  page_size?: number
  status?: string
}

export const containmentService = {
  async containAction(payload: ContainmentRequest): Promise<ContainmentActionResponse> {
    const res = await api.post<ContainmentActionResponse>('/v1/soc/actions/contain', payload)
    return res.data
  },

  async listActions(params: ListActionsParams = {}): Promise<PaginatedContainmentActions> {
    const res = await api.get<PaginatedContainmentActions>('/v1/soc/actions', { params })
    return res.data
  },

  async getAction(actionUuid: string): Promise<ContainmentActionResponse> {
    const res = await api.get<ContainmentActionResponse>(`/v1/soc/actions/${actionUuid}`)
    return res.data
  },

  async revertAction(actionUuid: string): Promise<ContainmentActionResponse> {
    const res = await api.post<ContainmentActionResponse>(`/v1/soc/actions/${actionUuid}/revert`)
    return res.data
  },

  async listPlaybookRuns(params: ListPlaybookRunsParams = {}): Promise<PaginatedPlaybookRuns> {
    const res = await api.get<PaginatedPlaybookRuns>('/v1/soc/playbooks/runs', { params })
    return res.data
  },

  async getPolicy(): Promise<ContainmentPolicyResponse> {
    const res = await api.get<ContainmentPolicyResponse>('/v1/soc/containment/policy')
    return res.data
  },

  async updatePolicy(payload: ContainmentPolicyUpdate): Promise<ContainmentPolicyResponse> {
    const res = await api.put<ContainmentPolicyResponse>('/v1/soc/containment/policy', payload)
    return res.data
  },
}
