/**
 * frontend/src/components/soc/LiveStreamIndicator.tsx
 * ───────────────────────────────────────────────────
 * Real-time visual indicator displaying active SSE connection status.
 */

import React from 'react'
import { Activity, AlertTriangle, RefreshCw, WifiOff } from 'lucide-react'
import type { StreamConnectionStatus } from '@/types/soc'
import { clsx } from 'clsx'

export interface LiveStreamIndicatorProps {
  status: StreamConnectionStatus
  reconnectAttempt?: number
  lastEventId?: number | null
  error?: string | null
  onReconnect?: () => void
  compact?: boolean
  className?: string
}

export function LiveStreamIndicator({
  status,
  reconnectAttempt = 0,
  lastEventId,
  error,
  onReconnect,
  compact = false,
  className,
}: LiveStreamIndicatorProps) {
  const getStatusConfig = () => {
    switch (status) {
      case 'connected':
        return {
          label: 'Live Stream',
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
          dotColor: 'bg-emerald-400',
          icon: Activity,
          animateDot: true,
        }
      case 'connecting':
        return {
          label: 'Connecting...',
          color: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
          dotColor: 'bg-sky-400',
          icon: RefreshCw,
          animateDot: true,
        }
      case 'reconnecting':
        return {
          label: reconnectAttempt > 0 ? `Reconnecting (${reconnectAttempt})` : 'Reconnecting...',
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
          dotColor: 'bg-amber-400',
          icon: RefreshCw,
          animateDot: true,
        }
      case 'auth_revoked':
        return {
          label: 'Auth Revoked',
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
          dotColor: 'bg-rose-400',
          icon: AlertTriangle,
          animateDot: false,
        }
      case 'error':
        return {
          label: 'Stream Error',
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
          dotColor: 'bg-rose-400',
          icon: AlertTriangle,
          animateDot: false,
        }
      case 'disconnected':
      default:
        return {
          label: 'Offline',
          color: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
          dotColor: 'bg-gray-400',
          icon: WifiOff,
          animateDot: false,
        }
    }
  }

  const config = getStatusConfig()
  const StatusIcon = config.icon

  return (
    <div
      className={clsx(
        'inline-flex items-center gap-2 px-2.5 py-1 rounded-full border text-xs font-medium transition-colors select-none',
        config.color,
        className
      )}
      title={
        error
          ? `Status: ${config.label}\nError: ${error}`
          : lastEventId
          ? `Status: ${config.label}\nCursor: #${lastEventId}`
          : `Status: ${config.label}`
      }
    >
      {/* Pulse dot or spinner */}
      <span className="relative flex h-2 w-2">
        {config.animateDot && (
          <span
            className={clsx(
              'animate-ping absolute inline-flex h-full w-full rounded-full opacity-75',
              config.dotColor
            )}
          />
        )}
        <span className={clsx('relative inline-flex rounded-full h-2 w-2', config.dotColor)} />
      </span>

      {!compact && (
        <span className="flex items-center gap-1.5">
          <StatusIcon size={12} className="opacity-80" />
          <span>{config.label}</span>
          {lastEventId !== undefined && lastEventId !== null && status === 'connected' && (
            <span className="text-2xs opacity-75 font-mono">#{lastEventId}</span>
          )}
        </span>
      )}

      {(status === 'error' || status === 'disconnected') && onReconnect && (
        <button
          type="button"
          onClick={onReconnect}
          className="ml-1 p-0.5 hover:text-white rounded transition-colors"
          title="Retry Connection"
        >
          <RefreshCw size={11} />
        </button>
      )}
    </div>
  )
}
