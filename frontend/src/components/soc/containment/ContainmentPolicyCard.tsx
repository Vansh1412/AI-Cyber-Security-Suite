/**
 * frontend/src/components/soc/containment/ContainmentPolicyCard.tsx
 * ────────────────────────────────────────────────────────────────
 * Configuration card for tenant-wide automated threat containment policies.
 * Enforces optimistic concurrency control using policy_version and handles HTTP 409 conflicts.
 */

import React, { useEffect, useState } from 'react'
import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  Lock,
  RefreshCw,
  Save,
  Sliders,
} from 'lucide-react'
import type { ContainmentPolicyResponse, ContainmentPolicyUpdate } from '@/types/soc'

export interface ContainmentPolicyCardProps {
  policy: ContainmentPolicyResponse | null
  onUpdate: (update: ContainmentPolicyUpdate) => Promise<void>
  isUpdating: boolean
  isLoading: boolean
  onRefetch: () => void
}

export function ContainmentPolicyCard({
  policy,
  onUpdate,
  isUpdating,
  isLoading,
  onRefetch,
}: ContainmentPolicyCardProps) {
  const [autoContainment, setAutoContainment] = useState(false)
  const [autoBlacklist, setAutoBlacklist] = useState(false)
  const [autoQuarantine, setAutoQuarantine] = useState(false)
  const [autoIncidentBinding, setAutoIncidentBinding] = useState(false)
  const [minSeverity, setMinSeverity] = useState('CRITICAL')
  const [blacklistTtlSeconds, setBlacklistTtlSeconds] = useState(86400)
  const [conflictError, setConflictError] = useState<string | null>(null)
  const [saveSuccess, setSaveSuccess] = useState(false)

  // Synchronize state when policy changes
  useEffect(() => {
    if (policy) {
      setAutoContainment(policy.auto_containment_enabled)
      setAutoBlacklist(policy.auto_blacklist_enabled)
      setAutoQuarantine(policy.auto_quarantine_enabled)
      setAutoIncidentBinding(policy.auto_incident_binding_enabled)
      setMinSeverity(policy.containment_min_severity)
      setBlacklistTtlSeconds(policy.blacklist_ttl_seconds)
      setConflictError(null)
    }
  }, [policy])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!policy) return

    setConflictError(null)
    setSaveSuccess(false)

    const payload: ContainmentPolicyUpdate = {
      auto_containment_enabled: autoContainment,
      auto_blacklist_enabled: autoBlacklist,
      auto_quarantine_enabled: autoQuarantine,
      auto_incident_binding_enabled: autoIncidentBinding,
      containment_min_severity: minSeverity,
      blacklist_ttl_seconds: Number(blacklistTtlSeconds),
      policy_version: policy.policy_version,
    }

    try {
      await onUpdate(payload)
      setSaveSuccess(true)
      setTimeout(() => setSaveSuccess(false), 4000)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('409') || msg.toLowerCase().includes('conflict')) {
        setConflictError(
          'Policy conflict: another operator updated the containment configuration. Please refresh to load the latest settings before modifying.'
        )
      } else {
        setConflictError(msg || 'Failed to update containment policy.')
      }
    }
  }

  if (isLoading && !policy) {
    return (
      <div className="p-8 bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm flex items-center justify-center">
        <Loader2 size={24} className="animate-spin text-primary-500" />
      </div>
    )
  }

  return (
    <div className="bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-xl shadow-sm overflow-hidden">
      {/* Header */}
      <div className="p-5 border-b border-light-border dark:border-dark-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-gray-50/50 dark:bg-dark-bg/50">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-primary-500/10 text-primary-400 border border-primary-500/20">
            <Sliders size={20} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-gray-900 dark:text-white">
                Automated Containment Policy
              </h2>
              {policy && (
                <span className="text-2xs font-mono font-semibold px-2 py-0.5 rounded bg-gray-100 dark:bg-dark-bg text-gray-500 border border-light-border dark:border-dark-border">
                  v{policy.policy_version}
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500">
              Configure deterministic threshold rules for automatic threat mitigation and target quarantine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefetch}
            disabled={isLoading || isUpdating}
            className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-50"
            title="Reload Policy"
            aria-label="Reload containment policy"
          >
            <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="p-6 space-y-6">
        {/* Conflict Error Notice */}
        {conflictError && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start justify-between gap-3">
            <div className="flex items-start gap-2">
              <AlertCircle size={16} className="text-rose-400 shrink-0 mt-0.5" />
              <span>{conflictError}</span>
            </div>
            <button
              type="button"
              onClick={onRefetch}
              className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-medium text-2xs shrink-0"
            >
              Refresh Latest
            </button>
          </div>
        )}

        {/* Success Notice */}
        {saveSuccess && (
          <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 size={16} />
            <span>Containment policy updated successfully.</span>
          </div>
        )}

        {/* Master Kill-Switch */}
        <div className="p-4 rounded-xl bg-gray-50 dark:bg-dark-bg/60 border border-light-border dark:border-dark-border flex items-center justify-between">
          <div>
            <span className="text-sm font-semibold text-gray-900 dark:text-white block">
              Master Auto-Containment Kill-Switch
            </span>
            <p className="text-xs text-gray-500">
              When disabled, all automated containment playbooks are globally suspended for this tenant.
            </p>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={autoContainment}
              onChange={(e) => setAutoContainment(e.target.checked)}
              disabled={isUpdating}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-300 peer-focus:outline-none rounded-full peer dark:bg-dark-border peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600" />
          </label>
        </div>

        {/* Playbook Toggles Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Auto Blacklist */}
          <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-900 dark:text-white">
                Auto-Blacklist
              </span>
              <input
                type="checkbox"
                checked={autoBlacklist}
                onChange={(e) => setAutoBlacklist(e.target.checked)}
                disabled={isUpdating || !autoContainment}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>
            <p className="text-2xs text-gray-500">
              Automatically inserts confirmed indicators into the dynamic blacklist upon qualification.
            </p>
          </div>

          {/* Auto Quarantine */}
          <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-900 dark:text-white">
                Auto-Quarantine
              </span>
              <input
                type="checkbox"
                checked={autoQuarantine}
                onChange={(e) => setAutoQuarantine(e.target.checked)}
                disabled={isUpdating || !autoContainment}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>
            <p className="text-2xs text-gray-500">
              Suspends monitored targets when threshold is met (&ge; 3 active high/critical alerts in 10 minutes).
            </p>
          </div>

          {/* Auto Incident Binding */}
          <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-900 dark:text-white">
                Incident Binding
              </span>
              <input
                type="checkbox"
                checked={autoIncidentBinding}
                onChange={(e) => setAutoIncidentBinding(e.target.checked)}
                disabled={isUpdating || !autoContainment}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>
            <p className="text-2xs text-gray-500">
              Automatically creates or binds qualifying containment alerts to an open SOC incident container.
            </p>
          </div>
        </div>

        {/* Severity & TTL Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          {/* Minimum Severity */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Minimum Alert Severity for Auto-Containment
            </label>
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
              disabled={isUpdating || !autoContainment}
              className="w-full px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            >
              <option value="CRITICAL">CRITICAL (Recommended)</option>
              <option value="HIGH">HIGH (High & Critical)</option>
            </select>
          </div>

          {/* Blacklist TTL */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              Blacklist TTL Duration (Seconds)
            </label>
            <input
              type="number"
              min={60}
              max={2592000}
              value={blacklistTtlSeconds}
              onChange={(e) => setBlacklistTtlSeconds(Number(e.target.value))}
              disabled={isUpdating || !autoContainment}
              className="w-full px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
            />
            <p className="text-2xs text-gray-500 mt-1">
              Default: 86400 (24 hours). Minimum 60s, maximum 30 days.
            </p>
          </div>
        </div>

        {/* Submit */}
        <div className="pt-4 border-t border-light-border dark:border-dark-border flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-2xs text-gray-400">
            <Lock size={12} />
            <span>Optimistic locking enabled. Changes increment policy version.</span>
          </div>

          <button
            type="submit"
            disabled={isUpdating}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-primary-600 hover:bg-primary-500 text-white shadow-sm transition-all disabled:opacity-50"
          >
            {isUpdating ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Save size={14} />
            )}
            <span>Save Containment Policy</span>
          </button>
        </div>
      </form>
    </div>
  )
}
