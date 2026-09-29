/**
 * frontend/src/components/soc/notifications/NotificationPreferencesCard.tsx
 * ─────────────────────────────────────────────────────────────────────────
 * Configuration card for notification channels (in-app, email, webhook),
 * secret rotation with >= 32 character validation, masked previews, and circuit-breaker telemetry.
 */

import React, { useEffect, useState } from 'react'
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Key,
  Link as LinkIcon,
  Loader2,
  RefreshCw,
  Save,
  Sliders,
} from 'lucide-react'
import type {
  NotificationPreferenceResponse,
  NotificationPreferenceUpdate,
} from '@/types/soc'

export interface NotificationPreferencesCardProps {
  preferences: NotificationPreferenceResponse | null
  onUpdate: (update: NotificationPreferenceUpdate) => Promise<void>
  isUpdating: boolean
  isLoading: boolean
  onRefetch: () => void
}

export function NotificationPreferencesCard({
  preferences,
  onUpdate,
  isUpdating,
  isLoading,
  onRefetch,
}: NotificationPreferencesCardProps) {
  const [inAppEnabled, setInAppEnabled] = useState(true)
  const [emailEnabled, setEmailEnabled] = useState(false)
  const [webhookEnabled, setWebhookEnabled] = useState(false)
  const [webhookUrl, setWebhookUrl] = useState('')
  const [minSeverity, setMinSeverity] = useState('HIGH')
  const [newSecret, setNewSecret] = useState('')
  const [isEnteringSecret, setIsEnteringSecret] = useState(false)
  const [rotateSecret, setRotateSecret] = useState(false)
  const [clearSecret, setClearSecret] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    if (preferences) {
      setInAppEnabled(preferences.in_app_enabled)
      setEmailEnabled(preferences.email_enabled)
      setWebhookEnabled(preferences.webhook_enabled)
      setWebhookUrl(preferences.webhook_url || '')
      setMinSeverity(preferences.min_severity || 'HIGH')
      setNewSecret('')
      setIsEnteringSecret(false)
      setRotateSecret(false)
      setClearSecret(false)
      setError(null)
    }
  }, [preferences])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccess(false)

    // Validate webhook URL if webhook enabled
    const trimmedUrl = webhookUrl.trim()
    if (webhookEnabled) {
      if (!trimmedUrl) {
        setError('Webhook URL is required when webhook delivery is enabled.')
        return
      }
      if (!trimmedUrl.startsWith('http://') && !trimmedUrl.startsWith('https://')) {
        setError('Webhook URL must start with http:// or https://')
        return
      }
    }

    // Validate new secret length if provided
    const trimmedSecret = newSecret.trim()
    if (isEnteringSecret && trimmedSecret) {
      if (trimmedSecret.length < 32) {
        setError('Webhook signing secret must be at least 32 characters long.')
        return
      }
      if (new Set(trimmedSecret).size < 2) {
        setError('Webhook signing secret has insufficient complexity / entropy.')
        return
      }
    }

    const payload: NotificationPreferenceUpdate = {
      in_app_enabled: inAppEnabled,
      email_enabled: emailEnabled,
      webhook_enabled: webhookEnabled,
      webhook_url: trimmedUrl || null,
      min_severity: minSeverity,
    }

    if (clearSecret) {
      payload.clear_webhook_secret = true
    } else if (rotateSecret) {
      payload.rotate_secret = true
    } else if (isEnteringSecret && trimmedSecret) {
      payload.webhook_secret = trimmedSecret
    }

    try {
      await onUpdate(payload)
      setSuccess(true)
      setIsEnteringSecret(false)
      setNewSecret('')
      setRotateSecret(false)
      setClearSecret(false)
      setTimeout(() => setSuccess(false), 4000)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg || 'Failed to update notification preferences.')
    }
  }

  const formatTimestamp = (dateStr?: string | null) => {
    if (!dateStr) return '—'
    try {
      return new Date(dateStr).toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium',
      })
    } catch {
      return dateStr
    }
  }

  if (isLoading && !preferences) {
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
            <h2 className="text-base font-bold text-gray-900 dark:text-white">
              Notification & Webhook Preferences
            </h2>
            <p className="text-xs text-gray-500">
              Manage alert dispatch channels, severity thresholds, and encrypted webhook egress
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onRefetch}
          disabled={isLoading || isUpdating}
          className="p-1.5 rounded-lg border border-light-border dark:border-dark-border text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-hover transition-colors disabled:opacity-50"
          title="Reload Preferences"
          aria-label="Reload preferences"
        >
          <RefreshCw size={14} className={isLoading ? 'animate-spin' : ''} />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="p-6 space-y-6">
        {/* Error Alert */}
        {error && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-xs text-rose-400 flex items-center gap-2">
            <AlertCircle size={16} className="shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Success Alert */}
        {success && (
          <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 size={16} className="shrink-0" />
            <span>Notification preferences updated successfully.</span>
          </div>
        )}

        {/* Circuit Breaker Warning Banner */}
        {preferences?.circuit_broken && (
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-1.5">
            <div className="flex items-center gap-2 font-semibold text-amber-400">
              <AlertTriangle size={16} />
              <span>Webhook Circuit Breaker Tripped</span>
            </div>
            <p className="leading-relaxed">
              Automated webhook egress was suspended due to 5 consecutive delivery timeouts or connection failures (tripped at {formatTimestamp(preferences.circuit_broken_at)}). Please verify your webhook receiver endpoint and save preferences to reset delivery.
            </p>
          </div>
        )}

        {/* Dispatch Channels */}
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Dispatch Channels
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* In-App Notifications */}
            <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-gray-900 dark:text-white block">
                  In-App Notification
                </span>
                <span className="text-2xs text-gray-500">
                  Deliver notifications to web console
                </span>
              </div>
              <input
                type="checkbox"
                checked={inAppEnabled}
                onChange={(e) => setInAppEnabled(e.target.checked)}
                disabled={isUpdating}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>

            {/* Email Alerts */}
            <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-gray-900 dark:text-white block">
                  Email Alerts
                </span>
                <span className="text-2xs text-gray-500">
                  Dispatch email for qualifying threats
                </span>
              </div>
              <input
                type="checkbox"
                checked={emailEnabled}
                onChange={(e) => setEmailEnabled(e.target.checked)}
                disabled={isUpdating}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>

            {/* Webhook Delivery */}
            <div className="p-4 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/40 dark:bg-dark-bg/40 flex items-center justify-between">
              <div>
                <span className="text-xs font-semibold text-gray-900 dark:text-white block">
                  Webhook Delivery
                </span>
                <span className="text-2xs text-gray-500">
                  HTTP POST egress with HMAC signature
                </span>
              </div>
              <input
                type="checkbox"
                checked={webhookEnabled}
                onChange={(e) => setWebhookEnabled(e.target.checked)}
                disabled={isUpdating}
                className="w-4 h-4 rounded text-primary-600 focus:ring-primary-500 border-gray-300 dark:border-dark-border"
              />
            </div>
          </div>
        </div>

        {/* Severity Threshold */}
        <div className="space-y-1.5">
          <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300">
            Minimum Severity for Notification Dispatch
          </label>
          <select
            value={minSeverity}
            onChange={(e) => setMinSeverity(e.target.value)}
            disabled={isUpdating}
            className="w-full sm:w-64 px-3 py-2 text-xs rounded-lg border border-light-border dark:border-dark-border bg-gray-50 dark:bg-dark-bg text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500/40"
          >
            <option value="CRITICAL">CRITICAL Only</option>
            <option value="HIGH">HIGH (High & Critical)</option>
            <option value="MEDIUM">MEDIUM (Medium, High & Critical)</option>
            <option value="LOW">LOW (Low and above)</option>
            <option value="INFO">INFO (All Events)</option>
          </select>
        </div>

        {/* Webhook Configuration Section */}
        <div className="p-5 rounded-xl border border-light-border dark:border-dark-border bg-gray-50/30 dark:bg-dark-bg/30 space-y-4">
          <div className="flex items-center gap-2">
            <LinkIcon size={16} className="text-primary-400" />
            <h3 className="text-xs font-semibold text-gray-900 dark:text-white uppercase tracking-wider">
              Webhook Endpoint Configuration
            </h3>
          </div>

          {/* Webhook URL Input */}
          <div>
            <label className="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1">
              Webhook Receiver URL
            </label>
            <input
              type="url"
              placeholder="https://siem.corp.internal/api/v1/soc-alerts"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              disabled={isUpdating || !webhookEnabled}
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-light-border dark:border-dark-border bg-white dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40 disabled:opacity-50"
            />
            <p className="text-2xs text-gray-500 mt-1">
              Must begin with https:// or http://. Payload is signed with HMAC-SHA256 in the <code className="font-mono">X-SOC-Signature</code> header.
            </p>
          </div>

          {/* Webhook Secret Management */}
          <div className="space-y-2 pt-2 border-t border-light-border dark:border-dark-border">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-1.5">
                <Key size={13} className="text-gray-400" />
                <span>HMAC Signing Secret</span>
              </label>

              {preferences?.has_webhook_secret && !clearSecret && !rotateSecret && !isEnteringSecret && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setIsEnteringSecret(true)
                      setClearSecret(false)
                      setRotateSecret(false)
                    }}
                    className="text-2xs text-primary-400 hover:underline"
                  >
                    Change Secret
                  </button>
                  <span className="text-gray-400">|</span>
                  <button
                    type="button"
                    onClick={() => {
                      setRotateSecret(true)
                      setIsEnteringSecret(false)
                      setClearSecret(false)
                    }}
                    className="text-2xs text-purple-400 hover:underline"
                  >
                    Auto-Rotate
                  </button>
                  <span className="text-gray-400">|</span>
                  <button
                    type="button"
                    onClick={() => {
                      setClearSecret(true)
                      setIsEnteringSecret(false)
                      setRotateSecret(false)
                    }}
                    className="text-2xs text-rose-400 hover:underline"
                  >
                    Clear
                  </button>
                </div>
              )}
            </div>

            {/* Current Secret Preview */}
            {preferences?.has_webhook_secret && !isEnteringSecret && !rotateSecret && !clearSecret && (
              <div className="p-2.5 rounded-lg bg-gray-100 dark:bg-dark-bg border border-light-border dark:border-dark-border flex items-center justify-between text-xs">
                <span className="font-mono text-gray-600 dark:text-gray-300">
                  {preferences.webhook_secret_preview || '••••••••••••••••'}
                </span>
                <span className="text-2xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                  Active (AES-256 Encrypted)
                </span>
              </div>
            )}

            {/* Clear secret staged */}
            {clearSecret && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300 flex items-center justify-between">
                <span>Secret will be removed on save.</span>
                <button
                  type="button"
                  onClick={() => setClearSecret(false)}
                  className="text-2xs text-white hover:underline"
                >
                  Cancel
                </button>
              </div>
            )}

            {/* Auto-rotate staged */}
            {rotateSecret && (
              <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20 text-xs text-purple-300 flex items-center justify-between">
                <span>Server will generate a new cryptographically secure secret on save.</span>
                <button
                  type="button"
                  onClick={() => setRotateSecret(false)}
                  className="text-2xs text-white hover:underline"
                >
                  Cancel
                </button>
              </div>
            )}

            {/* Manual Secret Input */}
            {(!preferences?.has_webhook_secret || isEnteringSecret) && !clearSecret && !rotateSecret && (
              <div className="space-y-1.5">
                <input
                  type="password"
                  placeholder="Enter new 32+ character signing secret..."
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                  disabled={isUpdating || !webhookEnabled}
                  className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-light-border dark:border-dark-border bg-white dark:bg-dark-bg text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
                />
                <div className="flex items-center justify-between text-2xs text-gray-500">
                  <span>Minimum 32 characters required for secure HMAC-SHA256.</span>
                  <span
                    className={
                      newSecret.length >= 32 ? 'text-emerald-400' : 'text-amber-400'
                    }
                  >
                    {newSecret.length}/32 chars
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Submit Button */}
        <div className="pt-4 border-t border-light-border dark:border-dark-border flex items-center justify-between">
          <span className="text-2xs text-gray-500">
            Last updated: {formatTimestamp(preferences?.updated_at)}
          </span>

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
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  )
}
