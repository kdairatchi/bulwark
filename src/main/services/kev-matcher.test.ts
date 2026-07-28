import { describe, it, expect, beforeEach } from 'vitest'
import path from 'path'
import {
  loadKevCatalog,
  getKevCatalogInfo,
  matchKevAgainstApps,
  matchesKevAlias,
  kevHitsToCloudFindings,
  resetKevCatalogCache,
} from './kev-matcher'
import type { InstalledApp } from '../platform/types'

const CATALOG = path.resolve(__dirname, '../../../rules/security/kev.json')

function app(name: string, version = '1.0.0'): InstalledApp {
  return { name, version, publisher: '', installDate: '', sizeKb: 0 }
}

describe('kev-matcher', () => {
  beforeEach(() => resetKevCatalogCache())

  it('loads curated KEV catalog', () => {
    const info = getKevCatalogInfo(CATALOG)
    expect(info.entryCount).toBeGreaterThan(30)
    expect(info.version).toMatch(/^\d+\./)
    expect(loadKevCatalog(CATALOG).entries.every((e) => e.cveId.startsWith('CVE-'))).toBe(true)
  })

  it('matches package-style aliases (libssl3 → openssl/libssl)', () => {
    expect(matchesKevAlias('libssl3', 'libssl')).toBe(true)
    expect(matchesKevAlias('Google Chrome', 'chrome')).toBe(true)
    expect(matchesKevAlias('curl', 'curl')).toBe(true)
    expect(matchesKevAlias('curling', 'curl')).toBe(false)
    expect(matchesKevAlias('Microsoft Office 2019', 'microsoft office')).toBe(true)
  })

  it('flags vulnerable curl below fix version', () => {
    const hits = matchKevAgainstApps([app('curl', '7.88.1')], { catalogPath: CATALOG })
    expect(hits.some((h) => h.cveId === 'CVE-2023-38545')).toBe(true)
    const findings = kevHitsToCloudFindings(hits)
    expect(findings.some((f) => f.category === 'kev' && f.subjectName === 'CVE-2023-38545')).toBe(true)
    expect(findings.find((f) => f.subjectName === 'CVE-2023-38545')?.level).toBe('likely_affected')
  })

  it('skips curl when version is already fixed', () => {
    const hits = matchKevAgainstApps([app('curl', '8.5.0')], { catalogPath: CATALOG })
    expect(hits.some((h) => h.cveId === 'CVE-2023-38545')).toBe(false)
  })

  it('flags Log4j with version gate', () => {
    const hits = matchKevAgainstApps([app('log4j-core', '2.14.1')], { catalogPath: CATALOG })
    expect(hits.some((h) => h.cveId === 'CVE-2021-44228')).toBe(true)
  })

  it('flags ScreenConnect product match without version gate as potential', () => {
    const hits = matchKevAgainstApps([app('ConnectWise ScreenConnect', '22.0')], { catalogPath: CATALOG })
    expect(hits.some((h) => h.cveId === 'CVE-2024-1709' && h.ransomware)).toBe(true)
    const f = kevHitsToCloudFindings(hits).find((x) => x.subjectName === 'CVE-2024-1709')
    expect(f?.level).toBe('potential_match')
    expect(f?.reason).toContain('ransomware')
  })

  it('does not flag unrelated apps', () => {
    const hits = matchKevAgainstApps([app('Normal Text Editor', '1.0')], { catalogPath: CATALOG })
    expect(hits).toHaveLength(0)
  })
})
