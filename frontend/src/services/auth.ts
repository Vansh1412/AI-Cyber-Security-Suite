import api from './api'
import type { AuthTokens, User } from '@/types'

export const authService = {
  async register(email: string, password: string): Promise<User> {
    const res = await api.post('/v1/auth/register', { email, password })
    return res.data
  },

  async login(email: string, password: string): Promise<AuthTokens> {
    const res = await api.post('/v1/auth/login', { email, password })
    const tokens: AuthTokens = res.data
    localStorage.setItem('access_token', tokens.access_token)
    // Mirror token to chrome.storage.local for the browser extension
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cr = (window as any).chrome
      if (cr?.storage?.local) {
        const apiBase = (import.meta as any).env?.VITE_API_URL ?? 'http://localhost:8000'
        cr.storage.local.set({ auth_token: tokens.access_token, api_base: apiBase })
      }
    } catch { /* extension not installed — safe to ignore */ }
    return tokens
  },

  async getMe(): Promise<User> {
    const res = await api.get('/v1/auth/me')
    return res.data
  },

  logout() {
    localStorage.removeItem('access_token')
    // Clear extension token on logout
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const cr = (window as any).chrome
      if (cr?.storage?.local) {
        cr.storage.local.remove(['auth_token'])
      }
    } catch { /* extension not installed */ }
  },

  isAuthenticated(): boolean {
    return !!localStorage.getItem('access_token')
  },
}
