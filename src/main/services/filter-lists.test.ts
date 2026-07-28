import { describe, it, expect } from 'vitest'
import { FILTER_LIST_CATALOG } from './filter-lists'

describe('filter-lists · catalog', () => {
  it('has unique ids and https URLs', () => {
    const ids = FILTER_LIST_CATALOG.map((l) => l.id)
    expect(new Set(ids).size).toBe(ids.length)
    for (const l of FILTER_LIST_CATALOG) {
      expect(l.url.startsWith('https://')).toBe(true)
      expect(l.name.length).toBeGreaterThan(0)
      expect(l.description.length).toBeGreaterThan(0)
    }
  })

  it('enables at least one list by default (on-by-default protection)', () => {
    expect(FILTER_LIST_CATALOG.some((l) => l.enabledByDefault)).toBe(true)
  })
})
