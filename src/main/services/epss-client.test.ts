import { describe, it, expect, vi } from 'vitest'
import { fetchEpssScores, enrichFindingsWithEpss } from './epss-client'
import type { InventoryFinding } from './desktop-inventory'

describe('epss-client', () => {
  it('parses EPSS scores from FIRST.org-shaped responses', async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        data: [
          { cve: 'CVE-2023-38545', epss: '0.78483', percentile: '0.99539' },
        ],
      }),
    })) as unknown as typeof fetch

    const scores = await fetchEpssScores(['CVE-2023-38545', 'not-a-cve'], { fetchFn })
    expect(scores.get('CVE-2023-38545')?.epss).toBeCloseTo(0.78483, 4)
    expect(scores.size).toBe(1)
  })

  it('soft-fails on network errors', async () => {
    const fetchFn = vi.fn(async () => { throw new Error('boom') }) as unknown as typeof fetch
    const scores = await fetchEpssScores(['CVE-2023-38545'], { fetchFn })
    expect(scores.size).toBe(0)
  })

  it('enriches finding reasons and elevates high-EPSS potentials', () => {
    const findings: InventoryFinding[] = [
      {
        level: 'potential_match',
        subjectName: 'CVE-2023-38545',
        reason: 'kev_product_match:curl@7.88.1',
        category: 'kev',
      },
      {
        level: 'safe',
        subjectName: 'device_posture',
        reason: 'posture_score_90',
        category: 'health',
      },
    ]
    const scores = new Map([
      ['CVE-2023-38545', { cve: 'CVE-2023-38545', epss: 0.78, percentile: 0.99 }],
    ])
    const out = enrichFindingsWithEpss(findings, scores)
    expect(out[0].reason).toContain('epss=0.7800')
    expect(out[0].level).toBe('likely_affected')
    expect(out[1].reason).toBe('posture_score_90')
  })
})
