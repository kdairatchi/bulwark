import { describe, expect, it } from 'vitest'
import {
  UTILITY_TWEAK_CATALOG,
  UTILITY_TWEAK_GROUP_ORDER,
} from './utility-tweaks.catalog'

describe('utility-tweaks catalog', () => {
  it('has unique tweak IDs', () => {
    const ids = UTILITY_TWEAK_CATALOG.map((t) => t.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('contains only valid groups and complete metadata', () => {
    for (const tweak of UTILITY_TWEAK_CATALOG) {
      expect(tweak.id.length).toBeGreaterThan(0)
      expect(tweak.name.length).toBeGreaterThan(0)
      expect(tweak.description.length).toBeGreaterThan(0)
      expect(UTILITY_TWEAK_GROUP_ORDER).toContain(tweak.group)
      expect(typeof tweak.requiresAdmin).toBe('boolean')
      expect(typeof tweak.check).toBe('function')
      expect(typeof tweak.apply).toBe('function')
      expect(typeof tweak.revert).toBe('function')
    }
  })

  it('covers essential and advanced groups', () => {
    for (const group of UTILITY_TWEAK_GROUP_ORDER) {
      expect(UTILITY_TWEAK_CATALOG.some((t) => t.group === group), group).toBe(true)
    }
  })
})
