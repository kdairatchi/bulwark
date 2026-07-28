import { describe, it, expect } from 'vitest'
import { findingPenalty, normalizeFindingCategory } from './store'

describe('finding taxonomy helpers', () => {
  it('normalizes categories', () => {
    expect(normalizeFindingCategory(' KEV ')).toBe('kev')
    expect(normalizeFindingCategory('vuln heuristic!')).toBe('vulnheuristic')
    expect(normalizeFindingCategory('')).toBeNull()
    expect(normalizeFindingCategory(1)).toBeNull()
  })

  it('weights KEV/ransomware higher than publisher noise', () => {
    const kev = findingPenalty({
      level: 'likely_affected',
      category: 'kev',
      reason: 'kev_product_match:x:ransomware',
    })
    const publisher = findingPenalty({
      level: 'likely_affected',
      category: 'publisher',
      reason: 'suspicious_app_name',
    })
    expect(kev).toBeGreaterThan(publisher)
  })
})
