/**
 * frontend/src/components/soc/monitoring/RegisterTargetModal.tsx
 * ─────────────────────────────────────────────────────────────
 * Modal for registering a new continuous probe monitoring target.
 * Enforces scheme validation, check interval bounds, SSRF advisory notice, and quota awareness.
 */

import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, Globe, Loader2, Radio, ShieldAlert, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { monitoringService } from '@/services/soc/monitoring'

export interface RegisterTargetModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
  currentActiveCount?: number
  quotaLimit?: number
}

const INTERVAL_OPTIONS = [
  { value: 5, label: 'Every 5 minutes (Real-time)' },
  { value: 15, label: 'Every 15 minutes' },
  { value: 30, label: 'Every 30 minutes' },
  { value: 60, label: 'Every 1 hour (Default)' },
  { value: 360, label: 'Every 6 hours' },
  { value: 720, label: 'Every 12 hours' },
  { value: 1440, label: 'Every 24 hours (Daily)' },
]

export function RegisterTargetModal({
  isOpen,
  onClose,
  onSuccess,
  currentActiveCount = 0,
  quotaLimit = 20,
}: RegisterTargetModalProps) {
  const [url, setUrl] = useState('')
  const [intervalMinutes, setIntervalMinutes] = useState(60)
  const [isSubmitting, setIsSubmitting] = useState(false)

  const isQuotaReached = currentActiveCount >= quotaLimit

  useEffect(() => {
    if (isOpen) {
      setUrl('')
      setIntervalMinutes(60)
      setIsSubmitting(false)
    }
  }, [isOpen])

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmedUrl = url.trim()
    if (!trimmedUrl || isSubmitting) return

    if (!trimmedUrl.startsWith('http://') && !trimmedUrl.startsWith('https://')) {
      toast.error('Target URL must begin with http:// or https://')
      return
    }

    setIsSubmitting(true)
    try {
      await monitoringService.registerTarget({
        url: trimmedUrl,
        check_interval_minutes: Number(intervalMinutes),
      })
      toast.success('Monitoring target registered successfully.')
      onSuccess()
      onClose()
    } catch (err: unknown) {
      const errorObj = err as {
        response?: { status?: number; data?: { detail?: string } }
      }
      const status = errorObj?.response?.status
      const msg = errorObj?.response?.data?.detail

      if (status === 400) {
        toast.error(
          typeof msg === 'string'
            ? msg
            : 'SSRF Validation Error: Target points to a private or disallowed network address.'
        )
      } else if (status === 429) {
        toast.error('Target limit exceeded. Please deactivate an existing target before registering a new one.')
      } else if (status === 422) {
        toast.error(typeof msg === 'string' ? msg : 'Validation error in target URL or interval.')
      } else {
        toast.error('Failed to register target. Please verify the URL and try again.')
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
                <Radio size={18} />
              </div>
              <div>
                <h3 className="text-base font-bold text-gray-900 dark:text-white">
                  Add Monitored Target
                </h3>
                <p className="text-2xs text-gray-500 mt-0.5">
                  Register a URL for autonomous scheduled probe surveillance.
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
            {/* Quota Warning Banner if Near / At Limit */}
            {isQuotaReached && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-2xs space-y-1">
                <p className="font-bold">Active Target Quota Reached ({currentActiveCount} / {quotaLimit})</p>
                <p className="text-3xs text-gray-400">
                  You have reached the maximum active monitoring quota. Deactivate or delete an existing target before adding another.
                </p>
              </div>
            )}

            {/* Target URL Input */}
            <div className="space-y-1.5">
              <label htmlFor="register-target-url" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Target URL <span className="text-rose-400">*</span>
              </label>
              <div className="relative">
                <input
                  id="register-target-url"
                  type="url"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl pl-8 pr-3 py-2.5 focus:outline-hidden focus:border-primary-500 transition-colors font-mono"
                />
                <Globe size={14} className="absolute left-2.5 top-3 text-gray-400" />
              </div>
            </div>

            {/* Check Interval Dropdown */}
            <div className="space-y-1.5">
              <label htmlFor="register-target-interval" className="block text-2xs font-bold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Probe Check Interval <span className="text-rose-400">*</span>
              </label>
              <select
                id="register-target-interval"
                value={intervalMinutes}
                onChange={(e) => setIntervalMinutes(Number(e.target.value))}
                className="w-full bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border text-gray-800 dark:text-gray-200 text-xs rounded-xl px-3 py-2.5 focus:outline-hidden focus:border-primary-500 transition-colors"
              >
                {INTERVAL_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* SSRF Security Advisory Notice */}
            <div className="p-3 rounded-xl bg-light-surface dark:bg-dark-surface/60 border border-light-border dark:border-dark-border/80 text-2xs text-gray-500 space-y-1.5">
              <div className="flex items-center gap-1.5 font-bold text-gray-400 uppercase tracking-wider text-3xs">
                <ShieldAlert size={12} className="text-primary-400" />
                <span>Automated SSRF Protection</span>
              </div>
              <p className="text-3xs text-gray-400 leading-relaxed">
                Targets are validated prior to registration. Private networks (RFC 1918), local loopback interfaces (127.0.0.1, localhost), and cloud metadata endpoints are strictly blocked by network security controls.
              </p>
            </div>

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
                disabled={!url.trim() || isSubmitting || isQuotaReached}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-white bg-primary-600 hover:bg-primary-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-semibold shadow-xs"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 size={13} className="animate-spin" />
                    <span>Registering...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 size={13} />
                    <span>Start Monitoring</span>
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
