/**
 * frontend/src/__tests__/alert_filter_state.test.ts
 * ──────────────────────────────────────────────────
 * Unit tests for Alert Console URL search parameter synchronization,
 * filter serialization/deserialization, pagination boundaries, and resets.
 */

import { describe, expect, it } from 'vitest'
import type { AlertFilterState } from '@/components/soc/alerts/AlertFilterToolbar'

export function parseSearchParamsToFilters(params: URLSearchParams): {
  page: number
  pageSize: number
  filters: AlertFilterState
} {
  const rawPage = parseInt(params.get('page') || '1', 10)
  const page = isNaN(rawPage) || rawPage < 1 ? 1 : rawPage

  const rawSize = parseInt(params.get('page_size') || '20', 10)
  const pageSize = isNaN(rawSize) || rawSize < 1 ? 20 : Math.min(rawSize, 100)

  const filters: AlertFilterState = {
    status: params.get('status') || undefined,
    severity: params.get('severity') || undefined,
    indicator_type: params.get('indicator_type') || undefined,
    search: params.get('search') || undefined,
  }

  return { page, pageSize, filters }
}

export function serializeFiltersToSearchParams(
  currentParams: URLSearchParams,
  newFilters: Partial<AlertFilterState>,
  resetPage: boolean = true
): URLSearchParams {
  const next = new URLSearchParams(currentParams)

  if (resetPage) {
    next.set('page', '1')
  }

  Object.entries(newFilters).forEach(([key, val]) => {
    if (val !== undefined && val !== null && String(val).trim() !== '') {
      next.set(key, String(val).trim())
    } else {
      next.delete(key)
    }
  })

  return next
}

export function isFilterActive(filters: AlertFilterState): boolean {
  return Boolean(
    filters.status || filters.severity || filters.indicator_type || filters.search || filters.rule_name
  )
}

export function resetAllFilters(pageSize: number = 20): URLSearchParams {
  const params = new URLSearchParams()
  params.set('page', '1')
  params.set('page_size', String(pageSize))
  return params
}

describe('Alert Filter State & URL Search Params Synchronization', () => {
  it('parses default parameters when query string is empty', () => {
    const params = new URLSearchParams('')
    const { page, pageSize, filters } = parseSearchParamsToFilters(params)

    expect(page).toBe(1)
    expect(pageSize).toBe(20)
    expect(filters.status).toBeUndefined()
    expect(filters.severity).toBeUndefined()
    expect(filters.indicator_type).toBeUndefined()
    expect(filters.search).toBeUndefined()
  })

  it('correctly parses populated filter parameters', () => {
    const params = new URLSearchParams('page=3&page_size=50&status=OPEN&severity=HIGH&search=phish')
    const { page, pageSize, filters } = parseSearchParamsToFilters(params)

    expect(page).toBe(3)
    expect(pageSize).toBe(50)
    expect(filters.status).toBe('OPEN')
    expect(filters.severity).toBe('HIGH')
    expect(filters.search).toBe('phish')
  })

  it('bounds page_size to maximum 100', () => {
    const params = new URLSearchParams('page=1&page_size=500')
    const { pageSize } = parseSearchParamsToFilters(params)
    expect(pageSize).toBe(100)
  })

  it('sanitizes invalid page numbers back to 1', () => {
    const params = new URLSearchParams('page=-5')
    const { page } = parseSearchParamsToFilters(params)
    expect(page).toBe(1)

    const NaNParams = new URLSearchParams('page=abc')
    expect(parseSearchParamsToFilters(NaNParams).page).toBe(1)
  })

  it('serializes new filters and resets page to 1', () => {
    const current = new URLSearchParams('page=4&status=OPEN')
    const updated = serializeFiltersToSearchParams(current, { severity: 'CRITICAL' })

    expect(updated.get('page')).toBe('1')
    expect(updated.get('status')).toBe('OPEN')
    expect(updated.get('severity')).toBe('CRITICAL')
  })

  it('removes keys when filter value is cleared or empty', () => {
    const current = new URLSearchParams('page=1&status=OPEN&severity=HIGH')
    const updated = serializeFiltersToSearchParams(current, { status: undefined, severity: '' })

    expect(updated.has('status')).toBe(false)
    expect(updated.has('severity')).toBe(false)
  })

  it('accurately identifies active filter state', () => {
    expect(isFilterActive({})).toBe(false)
    expect(isFilterActive({ status: 'OPEN' })).toBe(true)
    expect(isFilterActive({ severity: 'HIGH' })).toBe(true)
    expect(isFilterActive({ search: 'evil.com' })).toBe(true)
  })

  it('resetAllFilters clears all filters while preserving page_size', () => {
    const reset = resetAllFilters(50)
    expect(reset.get('page')).toBe('1')
    expect(reset.get('page_size')).toBe('50')
    expect(reset.has('status')).toBe(false)
    expect(reset.has('severity')).toBe(false)
    expect(reset.has('search')).toBe(false)
  })
})
