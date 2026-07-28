import { describe, expect, it, vi, afterEach } from 'vitest'
import { mkdtempSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { guessNvdCpes, queryNvd, scanAppsWithNvd, toCpe23 } from './nvd-client'
import type { InstalledApp } from '../platform/types'

const app = (overrides: Partial<InstalledApp> = {}): InstalledApp => ({
  name: 'curl', version: '7.88.1', publisher: '', installDate: '', sizeKb: 0, ...overrides,
})

describe('nvd-client', () => {
  const cacheDirs: string[] = []
  afterEach(() => {
    for (const dir of cacheDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
  })

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

  it('uses fresh cache entries and refreshes stale entries with a bounded window', async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), 'nvd-client-'))
    cacheDirs.push(cacheDir)
    const firstFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      headers: new Headers({ etag: 'etag-1', 'last-modified': 'Tue, 01 Jan 2030 00:00:00 GMT' }),
      json: async () => ({ vulnerabilities: [{ cve: { id: 'CVE-2030-0001' } }] }),
    })) as unknown as typeof fetch
    const cpe = { vendor: 'haxx', product: 'curl', version: '7.88.1' }
    await queryNvd(cpe, { fetchFn: firstFetch, cacheDir, nowMs: Date.parse('2030-01-02T00:00:00Z') })

    const freshFetch = vi.fn()
    expect(await queryNvd(cpe, { fetchFn: freshFetch, cacheDir, nowMs: Date.parse('2030-01-02T01:00:00Z') })).toEqual([
      expect.objectContaining({ id: 'CVE-2030-0001' }),
    ])
    expect(freshFetch).not.toHaveBeenCalled()

    const staleFetch = vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toContain('lastModStartDate=')
      expect(url).toContain('lastModEndDate=')
      expect((init.headers as Record<string, string>)['If-None-Match']).toBe('etag-1')
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ vulnerabilities: [{ cve: { id: 'CVE-2030-0002' } }] }),
      }
    }) as unknown as typeof fetch
    const result = await queryNvd(cpe, {
      fetchFn: staleFetch,
      cacheDir,
      cacheTtlMs: 0,
      nowMs: Date.parse('2030-01-03T00:00:00Z'),
    })
    expect(result.map((v) => v.id)).toEqual(['CVE-2030-0001', 'CVE-2030-0002'])

    const offline = vi.fn(async () => { throw new Error('offline') }) as unknown as typeof fetch
    expect(await queryNvd(cpe, { fetchFn: offline, cacheDir, cacheTtlMs: 0, forceRefresh: true }))
      .toEqual([expect.objectContaining({ id: 'CVE-2030-0001' }), expect.objectContaining({ id: 'CVE-2030-0002' })])
  })
})
