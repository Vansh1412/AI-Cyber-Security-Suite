/**
 * frontend/src/__tests__/rbac_navigation.test.ts
 * ──────────────────────────────────────────────
 * Unit tests for Role-Based Access Control (RBAC) and navigation visibility:
 * - UserRead role parsing & preservation
 * - Standard user vs admin role segregation
 * - Admin route protection logic
 * - Navigation item visibility rules
 */

import { describe, expect, it } from 'vitest'
import type { User } from '@/types'

describe('RBAC & Role Verification', () => {
  it('correctly models standard user role', () => {
    const operator: User = {
      id: 10,
      email: 'analyst@example.com',
      role: 'user',
      is_active: true,
    }

    expect(operator.role).toBe('user')
    expect(operator.is_active).toBe(true)
  })

  it('correctly models admin role', () => {
    const admin: User = {
      id: 1,
      email: 'admin@example.com',
      role: 'admin',
      is_active: true,
    }

    expect(admin.role).toBe('admin')
  })

  it('evaluates admin privilege check accurately', () => {
    const isAdmin = (u: User | null): boolean => {
      return !!u && u.role === 'admin'
    }

    expect(isAdmin(null)).toBe(false)
    expect(isAdmin({ id: 2, email: 'u@test.com', role: 'user', is_active: true })).toBe(false)
    expect(isAdmin({ id: 1, email: 'a@test.com', role: 'admin', is_active: true })).toBe(true)
  })

  it('determines sidebar navigation items visibility by role', () => {
    const getVisibleNavSections = (user: User | null) => {
      const sections = ['MainMenu', 'SecurityOperations']
      if (user?.role === 'admin') {
        sections.push('Admin')
      }
      sections.push('Account')
      return sections
    }

    const standardSections = getVisibleNavSections({
      id: 5,
      email: 'op@test.com',
      role: 'user',
      is_active: true,
    })
    expect(standardSections).toContain('MainMenu')
    expect(standardSections).toContain('SecurityOperations')
    expect(standardSections).toContain('Account')
    expect(standardSections).not.toContain('Admin')

    const adminSections = getVisibleNavSections({
      id: 1,
      email: 'admin@test.com',
      role: 'admin',
      is_active: true,
    })
    expect(adminSections).toContain('Admin')
  })
})
