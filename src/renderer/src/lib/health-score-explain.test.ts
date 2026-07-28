import { describe, it, expect } from 'vitest'
import { explainHealthScore } from './health-score-explain'

describe('health-score-explain', () => {
  it('rewards full recent coverage and a fresh scan', () => {
    const e = explainHealthScore({
      toolsTotal: 5,
      toolsRecent: 5,
      missingToolLabels: [],
      worstDiskUsage: 0.4,
      daysSinceScan: 0.5,
      hasLastScan: true,
    })
    expect(e.score).toBeGreaterThanOrEqual(90)
    expect(e.recommended).toMatch(/weekly|strong/i)
  })

  it('recommends a first scan when none exists', () => {
    const e = explainHealthScore({
      toolsTotal: 4,
      toolsRecent: 0,
      missingToolLabels: ['Malware', 'Cleaner'],
      worstDiskUsage: null,
      daysSinceScan: null,
      hasLastScan: false,
    })
    expect(e.score).toBeLessThan(50)
    expect(e.recommended).toMatch(/baseline|scan/i)
  })
})
