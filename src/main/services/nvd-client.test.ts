import { describe, expect, it, vi } from 'vitest'
import { guessNvdCpes, queryNvd, scanAppsWithNvd, toCpe23 } from './nvd-client'
import type { InstalledApp } from '../platform/types'

const app = (overrides: Partial<InstalledApp> = {}): InstalledApp => ({
  name: 'curl', version: '7.88.1', publisher: '', installDate: '', sizeKb: 0, ...overrides,
})

describe('nvd-client', () => {
  it('maps known inventory products to CPE candidates', () => {
    expect(guessNvdCpes(app())).toEqual([{ vendor: 'haxx', product: 'curl', version: '7.88.1' }])
    expect(guessNvdCpes(app({ name: 'Mystery' }))).toEqual([])
    expect(toCpe23({ vendor: 'haxx', product: 'curl', version: '7.88.1' }))
      .toBe('cpe:2.3:a:haxx:curl:7.88.1:*:*:*:*:*:*:*')
  })

  it('queries the NVD CPE endpoint and parses CVSS metadata', async () => {
    const fetchFn = vi.fn(async (url: string) => ({
      ok: true,
      json: async () => ({
        vulnerabilities: [{ cve: {
          id: 'CVE-2023-38545',
          descriptions: [{ lang: 'en', value: 'curl vulnerability' }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.8, baseSeverity: 'HIGH' } }] },
        } }],
      }),
    })) as unknown as typeof fetch
    const result = await queryNvd({ vendor: 'haxx', product: 'curl', version: '7.88.1' }, { fetchFn, apiKey: '' })
    expect(result[0]).toMatchObject({ id: 'CVE-2023-38545', severity: 'high', score: 8.8 })
    expect(fetchFn).toHaveBeenCalledWith(expect.stringContaining('isVulnerable='), expect.objectContaining({ headers: { Accept: 'application/json' } }))
  })

  it('emits bounded nvd findings and soft-fails on HTTP errors', async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      json: async () => ({ vulnerabilities: [{ cve: { id: 'CVE-2023-38545' } }] }),
    })) as unknown as typeof fetch
    const findings = await scanAppsWithNvd([app()], { fetchFn })
    expect(findings).toEqual([expect.objectContaining({ subjectName: 'CVE-2023-38545', category: 'nvd', level: 'likely_affected' })])
    const bad = vi.fn(async () => ({ ok: false })) as unknown as typeof fetch
    expect(await scanAppsWithNvd([app()], { fetchFn: bad })).toEqual([])
  })
})
