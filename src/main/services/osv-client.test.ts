import { describe, it, expect, vi } from 'vitest'
import { guessOsvPackages, queryOsv, scanAppsWithOsv } from './osv-client'
import type { InstalledApp } from '../platform/types'

describe('osv-client', () => {
  it('guesses Debian packages for common inventory names', () => {
    expect(guessOsvPackages({ name: 'openssl', version: '3.0.2', publisher: '', installDate: '', sizeKb: 0 })).toEqual([
      { name: 'openssl', ecosystem: 'Debian', version: '3.0.2' },
    ])
    expect(guessOsvPackages({ name: 'Mystery', version: '1.0', publisher: '', installDate: '', sizeKb: 0 })).toEqual([])
  })

  it('queryOsv maps CVE results and soft-fails on HTTP errors', async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      json: async () => ({ vulns: [{ id: 'CVE-2023-38545', summary: 'sockbuf' }, { id: 'GHSA-x' }] }),
    })) as unknown as typeof fetch
    const vulns = await queryOsv(
      { name: 'curl', ecosystem: 'Debian', version: '7.88.1' },
      { fetchFn, timeoutMs: 1000 },
    )
    expect(vulns).toEqual([{ id: 'CVE-2023-38545', summary: 'sockbuf' }])

    const bad = vi.fn(async () => ({ ok: false })) as unknown as typeof fetch
    expect(await queryOsv({ name: 'curl', ecosystem: 'Debian', version: '7.88.1' }, { fetchFn: bad })).toEqual([])
  })

  it('scanAppsWithOsv emits osv findings', async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      json: async () => ({ vulns: [{ id: 'CVE-2023-38545' }] }),
    })) as unknown as typeof fetch
    const apps: InstalledApp[] = [
      { name: 'curl', version: '7.88.1', publisher: '', installDate: '', sizeKb: 0 },
    ]
    const findings = await scanAppsWithOsv(apps, { fetchFn })
    expect(findings.some((f) => f.category === 'osv' && f.subjectName === 'CVE-2023-38545')).toBe(true)
  })
})
