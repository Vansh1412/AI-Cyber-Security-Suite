/**
 * frontend/src/services/soc/notifications.ts
 * ──────────────────────────────────────────
 * Typed API client for In-App Notifications & Webhook Preferences.
 */

import api from '@/services/api'
import type {
  MarkAllReadResponse,
  NotificationItem,
  NotificationListResponse,
  NotificationPreferenceResponse,
  NotificationPreferenceUpdate,
  UnreadCountResponse,
} from '@/types/soc'

export interface ListNotificationsParams {
  page?: number
  page_size?: number
  is_read?: boolean
  severity?: string
}

export const notificationsService = {
  async listNotifications(
    params: ListNotificationsParams = {}
  ): Promise<NotificationListResponse> {
    const res = await api.get<NotificationListResponse>('/v1/notifications', { params })
    return res.data
  },

  async getUnreadCount(): Promise<UnreadCountResponse> {
    const res = await api.get<UnreadCountResponse>('/v1/notifications/unread-count')
    return res.data
  },

  async markRead(notificationUuid: string): Promise<NotificationItem> {
    const res = await api.post<NotificationItem>(`/v1/notifications/${notificationUuid}/read`)
    return res.data
  },

  async markAllRead(): Promise<MarkAllReadResponse> {
    const res = await api.post<MarkAllReadResponse>('/v1/notifications/mark-all-read')
    return res.data
  },

  async getPreferences(): Promise<NotificationPreferenceResponse> {
    const res = await api.get<NotificationPreferenceResponse>('/v1/notifications/preferences')
    return res.data
  },

  async updatePreferences(
    payload: NotificationPreferenceUpdate
  ): Promise<NotificationPreferenceResponse> {
    const res = await api.put<NotificationPreferenceResponse>(
      '/v1/notifications/preferences',
      payload
    )
    return res.data
  },
}
