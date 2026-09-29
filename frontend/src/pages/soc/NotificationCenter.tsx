/**
 * frontend/src/pages/soc/NotificationCenter.tsx
 * ─────────────────────────────────────────────
 * Primary SOC console for In-App Notifications & Webhook Channel Preferences.
 * Features real-time unread synchronization, severity filtering, and encrypted webhook egress configuration.
 */

import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Bell, Sliders } from 'lucide-react'
import type { NotificationItem, NotificationPreferenceUpdate } from '@/types/soc'
import { notificationsService } from '@/services/soc/notifications'
import { useSSEStream } from '@/hooks/useSSEStream'
import { LiveStreamIndicator } from '@/components/soc/LiveStreamIndicator'
import { NotificationFilterToolbar } from '@/components/soc/notifications/NotificationFilterToolbar'
import { NotificationTable } from '@/components/soc/notifications/NotificationTable'
import { NotificationDetailDrawer } from '@/components/soc/notifications/NotificationDetailDrawer'
import { NotificationPreferencesCard } from '@/components/soc/notifications/NotificationPreferencesCard'

type ActiveTab = 'inbox' | 'preferences'

export default function NotificationCenter() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<ActiveTab>('inbox')

  // SSE stream connection
  const { status: sseStatus, lastEventId } = useSSEStream({ channel: 'soc' })

  // ── Inbox State ─────────────────────────────────────────────────────────────
  const [page, setPage] = useState(1)
  const [readFilter, setReadFilter] = useState<'ALL' | 'UNREAD' | 'READ'>('ALL')
  const [severityFilter, setSeverityFilter] = useState('')
  const [selectedNotification, setSelectedNotification] = useState<NotificationItem | null>(null)

  // Map read filter to boolean or undefined
  const isReadParam =
    readFilter === 'UNREAD' ? false : readFilter === 'READ' ? true : undefined

  // ── Query: Notifications List ───────────────────────────────────────────────
  const {
    data: notifsData,
    isLoading: isLoadingNotifs,
    isFetching: isFetchingNotifs,
    refetch: refetchNotifs,
  } = useQuery({
    queryKey: [
      'notifications',
      { page, is_read: isReadParam, severity: severityFilter || undefined },
    ],
    queryFn: () =>
      notificationsService.listNotifications({
        page,
        page_size: 20,
        is_read: isReadParam,
        severity: severityFilter || undefined,
      }),
  })

  // ── Query: Unread Count ─────────────────────────────────────────────────────
  const { data: unreadData, refetch: refetchUnread } = useQuery({
    queryKey: ['notifications-unread'],
    queryFn: () => notificationsService.getUnreadCount(),
  })

  // ── Query: Preferences ──────────────────────────────────────────────────────
  const {
    data: preferencesData,
    isLoading: isLoadingPreferences,
    refetch: refetchPreferences,
  } = useQuery({
    queryKey: ['notification-preferences'],
    queryFn: () => notificationsService.getPreferences(),
    enabled: activeTab === 'preferences',
  })

  // ── Mutation: Mark Single as Read ───────────────────────────────────────────
  const markReadMutation = useMutation({
    mutationFn: (uuid: string) => notificationsService.markRead(uuid),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      queryClient.invalidateQueries({ queryKey: ['notifications-unread'] })
      if (selectedNotification?.notification_uuid === updated.notification_uuid) {
        setSelectedNotification(updated)
      }
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      toast.error(msg || 'Failed to mark notification read.')
    },
  })

  // ── Mutation: Mark All as Read ──────────────────────────────────────────────
  const markAllReadMutation = useMutation({
    mutationFn: () => notificationsService.markAllRead(),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      queryClient.invalidateQueries({ queryKey: ['notifications-unread'] })
      toast.success(`Marked ${res.updated_count} notification(s) as read.`)
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err)
      toast.error(msg || 'Failed to mark all notifications read.')
    },
  })

  // ── Mutation: Update Preferences ────────────────────────────────────────────
  const preferencesMutation = useMutation({
    mutationFn: (payload: NotificationPreferenceUpdate) =>
      notificationsService.updatePreferences(payload),
    onSuccess: (updated) => {
      queryClient.setQueryData(['notification-preferences'], updated)
      queryClient.invalidateQueries({ queryKey: ['notification-preferences'] })
      toast.success('Notification preferences updated.')
    },
  })

  // When opening a drawer, mark as read automatically if unread
  const handleSelectNotification = (item: NotificationItem) => {
    setSelectedNotification(item)
    if (!item.is_read) {
      markReadMutation.mutate(item.notification_uuid)
    }
  }

  const unreadCount = unreadData?.unread_count ?? notifsData?.unread_count ?? 0

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 animate-in fade-in duration-150">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Notification Center
            </h1>
            <LiveStreamIndicator status={sseStatus} lastEventId={lastEventId} />
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Real-time security alerts, containment event notices, and encrypted webhook delivery management.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 bg-gray-100 dark:bg-dark-bg p-1 rounded-xl border border-light-border dark:border-dark-border text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveTab('inbox')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'inbox'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <Bell size={13} />
            <span>Inbox</span>
            {unreadCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-2xs font-bold bg-primary-500 text-white">
                {unreadCount}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('preferences')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeTab === 'preferences'
                ? 'bg-white dark:bg-dark-surface text-gray-900 dark:text-white shadow-xs'
                : 'text-gray-500 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            <Sliders size={13} />
            <span>Channels & Webhooks</span>
          </button>
        </div>
      </div>

      {/* Tab 1: Inbox */}
      {activeTab === 'inbox' && (
        <div className="space-y-4">
          <NotificationFilterToolbar
            readFilter={readFilter}
            onReadFilterChange={(f) => {
              setReadFilter(f)
              setPage(1)
            }}
            severityFilter={severityFilter}
            onSeverityFilterChange={(sev) => {
              setSeverityFilter(sev)
              setPage(1)
            }}
            onMarkAllRead={() => markAllReadMutation.mutate()}
            isMarkingAllRead={markAllReadMutation.isPending}
            unreadCount={unreadCount}
            onRefresh={() => {
              refetchNotifs()
              refetchUnread()
            }}
            isRefreshing={isFetchingNotifs}
          />

          <NotificationTable
            notifications={notifsData?.items || []}
            total={notifsData?.total || 0}
            page={page}
            pageSize={20}
            onPageChange={setPage}
            isLoading={isLoadingNotifs}
            onSelectNotification={handleSelectNotification}
            onMarkRead={(uuid) => markReadMutation.mutate(uuid)}
            markingReadUuid={markReadMutation.isPending ? markReadMutation.variables : null}
          />
        </div>
      )}

      {/* Tab 2: Channels & Webhooks */}
      {activeTab === 'preferences' && (
        <NotificationPreferencesCard
          preferences={preferencesData || null}
          onUpdate={async (update) => {
            await preferencesMutation.mutateAsync(update)
          }}
          isUpdating={preferencesMutation.isPending}
          isLoading={isLoadingPreferences}
          onRefetch={() => refetchPreferences()}
        />
      )}

      {/* Notification Detail Drawer */}
      <NotificationDetailDrawer
        notification={selectedNotification}
        isOpen={!!selectedNotification}
        onClose={() => setSelectedNotification(null)}
        onMarkRead={(uuid) => markReadMutation.mutate(uuid)}
        isMarkingRead={markReadMutation.isPending}
      />
    </div>
  )
}
