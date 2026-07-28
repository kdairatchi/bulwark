import { describe, it, expect } from 'vitest'
import {
  UTILITY_APP_CATALOG,
  UTILITY_CATEGORY_ORDER,
  isUtilityCatalogPackageId,
} from './utility-apps.catalog'
import { isValidAppIdForSource } from './software-updater'

describe('utility-apps catalog', () => {
  it('has unique winget package IDs', () => {
    const ids = UTILITY_APP_CATALOG.map((a) => a.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('only uses valid winget ID shapes', () => {
    for (const app of UTILITY_APP_CATALOG) {
      expect(isValidAppIdForSource(app.id, 'winget'), app.id).toBe(true)
      expect(app.name.length).toBeGreaterThan(0)
      expect(UTILITY_CATEGORY_ORDER).toContain(app.category)
    }
  })

  it('covers every category with at least one app', () => {
    for (const cat of UTILITY_CATEGORY_ORDER) {
      expect(UTILITY_APP_CATALOG.some((a) => a.category === cat), cat).toBe(true)
    }
  })

  it('identifies only package IDs from the curated catalog', () => {
    expect(isUtilityCatalogPackageId('Google.Chrome')).toBe(true)
    expect(isUtilityCatalogPackageId('Microsoft.VisualStudioCode')).toBe(true)
    expect(isUtilityCatalogPackageId('Microsoft.Teams')).toBe(true)
    expect(isUtilityCatalogPackageId('--source=msstore')).toBe(false)
  })
})
