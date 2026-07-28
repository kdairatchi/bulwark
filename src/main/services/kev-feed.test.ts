import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import {
  cisaVulnToKevEntry,
  cisaFeedToCatalog,
  mergeKevCatalogs,
  getEffectiveKevCatalog,
  setKevFeedCacheDirForTest,
} from './kev-feed'
import { loadKevCatalog, matchKevAgainstApps } from './kev-matcher'
import path from 'path'

const VENDORED = path.resolve(__dirname, '../../../rules/security/kev.json')

describe('kev-feed', () => {
  let cacheDir: string

  beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), 'kev-feed-'))
    setKevFeedCacheDirForTest(cacheDir)
  })

  afterEach(() => {
    setKevFeedCacheDirForTest(null)
    rmSync(cacheDir, { recursive: true, force: true })
  })

  it('converts CISA vulns to KEV entries with safe aliases', () => {
    const e = cisaVulnToKevEntry({
      cveID: 'CVE-2024-1709',
      vendorProject: 'ConnectWise',
      product: 'ScreenConnect',
      knownRansomwareCampaignUse: 'Known',
      requiredAction: 'Update',
      dateAdded: '2024-02-22',
    })
    expect(e?.cveId).toBe('CVE-2024-1709')
    expect(e?.ransomware).toBe(true)
    expect(e?.severity).toBe('critical')
    expect(e?.aliases.some((a) => a.includes('screenconnect'))).toBe(true)
    expect(e?.aliases.includes('windows')).toBe(false)
  })

  it('avoids bare generic product aliases like Windows', () => {
    const e = cisaVulnToKevEntry({
      cveID: 'CVE-2020-0001',
      vendorProject: 'Microsoft',
      product: 'Windows',
      knownRansomwareCampaignUse: 'Unknown',
    })
    expect(e?.aliases.includes('windows')).toBe(false)
    expect(e?.aliases.some((a) => a.includes('microsoft'))).toBe(true)
  })

  it('merges vendored version gates over live entries', () => {
    const vendored = loadKevCatalog(VENDORED)
    const live = cisaFeedToCatalog({
      catalogVersion: '2026.07.27',
      dateReleased: '2026-07-27T00:00:00Z',
      vulnerabilities: [
        {
          cveID: 'CVE-2023-38545',
          vendorProject: 'curl',
          product: 'curl',
          knownRansomwareCampaignUse: 'Unknown',
        },
        {
          cveID: 'CVE-2099-99999',
          vendorProject: 'Example',
          product: 'WidgetServer',
          knownRansomwareCampaignUse: 'Known',
        },
      ],
    })
    const merged = mergeKevCatalogs(vendored, live)
    const curl = merged.entries.find((e) => e.cveId === 'CVE-2023-38545')
    expect(curl?.vulnerableBelow).toBe('8.4.0')
    expect(merged.entries.some((e) => e.cveId === 'CVE-2099-99999' && e.ransomware)).toBe(true)
  })

  it('syncs live feed into cache and matches inventory', async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      text: async () => JSON.stringify({
        catalogVersion: 'test.1',
        dateReleased: '2026-01-01T00:00:00Z',
        vulnerabilities: [
          {
            cveID: 'CVE-2024-1709',
            vendorProject: 'ConnectWise',
            product: 'ScreenConnect',
            knownRansomwareCampaignUse: 'Known',
          },
        ],
      }),
    })) as unknown as typeof fetch

    const result = await getEffectiveKevCatalog(
      { sync: true },
      { fetchFn, cacheDir, vendoredPath: VENDORED },
    )
    expect(result.synced).toBe(true)
    expect(result.source).toBe('merged-live')
    expect(result.catalog.entries.length).toBeGreaterThan(40)

    const hits = matchKevAgainstApps(
      [{ name: 'ConnectWise ScreenConnect', version: '22', publisher: '', installDate: '', sizeKb: 0 }],
      { catalog: result.catalog },
    )
    expect(hits.some((h) => h.cveId === 'CVE-2024-1709')).toBe(true)
  })

  it('falls back to vendored when sync fails and cache empty', async () => {
    const fetchFn = vi.fn(async () => { throw new Error('network down') }) as unknown as typeof fetch
    const result = await getEffectiveKevCatalog(
      { sync: true },
      { fetchFn, cacheDir, vendoredPath: VENDORED },
    )
    expect(result.synced).toBe(false)
    expect(result.source).toBe('vendored')
    expect(result.error).toMatch(/network/i)
    expect(result.catalog.entries.length).toBeGreaterThan(30)
  })

  it('uses cache without network when sync=false', async () => {
    mkdirSync(cacheDir, { recursive: true })
    writeFileSync(join(cacheDir, 'cisa-kev.json'), JSON.stringify({
      catalogVersion: 'cached.1',
      vulnerabilities: [
        { cveID: 'CVE-2099-11111', vendorProject: 'Acme', product: 'RocketApp', knownRansomwareCampaignUse: 'Unknown' },
      ],
    }))
    const fetchFn = vi.fn() as unknown as typeof fetch
    const result = await getEffectiveKevCatalog(
      { sync: false },
      { fetchFn, cacheDir, vendoredPath: VENDORED },
    )
    expect(fetchFn).not.toHaveBeenCalled()
    expect(result.source).toBe('merged-cache')
    expect(result.catalog.entries.some((e) => e.cveId === 'CVE-2099-11111')).toBe(true)
  })
})
