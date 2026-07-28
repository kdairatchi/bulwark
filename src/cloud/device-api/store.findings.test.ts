import { describe, it, expect } from 'vitest'
import { findingPenalty, normalizeFindingCategory, normalizeFixRecommendation } from './store'

describe('finding taxonomy helpers', () => {
  it('normalizes categories', () => {
    expect(normalizeFindingCategory(' KEV ')).toBe('kev')
    expect(normalizeFindingCategory('vuln heuristic!')).toBe('vulnheuristic')
    expect(normalizeFindingCategory('')).toBeNull()
    expect(normalizeFindingCategory(1)).toBeNull()
  })

  it('normalizes fix recommendations', () => {
    expect(normalizeFixRecommendation('  Update curl  ')).toBe('Update curl')
    expect(normalizeFixRecommendation('')).toBeNull()
    expect(normalizeFixRecommendation(1)).toBeNull()
    expect(normalizeFixRecommendation('x'.repeat(300))?.length).toBe(240)
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
