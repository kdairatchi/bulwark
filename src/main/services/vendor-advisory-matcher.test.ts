import { describe, it, expect, beforeEach } from 'vitest'
import path from 'path'
import type { InstalledApp } from '../platform/types'
import {
  loadVendorAdvisoryCatalog,
  matchVendorAdvisoriesAgainstApps,
  advisoryHitsToCloudFindings,
  resetVendorAdvisoryCatalogCache,
  getVendorAdvisoryCatalogInfo,
} from './vendor-advisory-matcher'

const catalogPath = path.resolve(__dirname, '../../../rules/security/vendor-advisories.json')

function app(overrides: Partial<InstalledApp> = {}): InstalledApp {
  return {
    name: 'Normal App',
    version: '1.0',
    publisher: 'Example',
    installDate: '2020-01-01',
    sizeKb: 10,
    ...overrides,
  }
}

describe('vendor-advisory-matcher', () => {
  beforeEach(() => {
    resetVendorAdvisoryCatalogCache()
  })

  it('loads the curated catalog', () => {
    const info = getVendorAdvisoryCatalogInfo(catalogPath)
    expect(info.entryCount).toBeGreaterThanOrEqual(4)
    expect(info.version).toBeTruthy()
  })

  it('flags curl inside introduced..fixedIn as affected', () => {
    const hits = matchVendorAdvisoriesAgainstApps(
      [app({ name: 'curl', version: '7.88.1', publisher: 'curl' })],
      { catalogPath },
    )
    expect(hits.some((h) => h.cveId === 'CVE-2023-38545')).toBe(true)
    const findings = advisoryHitsToCloudFindings(hits)
    const f = findings.find((x) => x.subjectName === 'CVE-2023-38545')
    expect(f?.category).toBe('advisory')
    expect(f?.fixRecommendation).toMatch(/8\.4\.0/)
    expect(f?.confidence).toBe(0.9)
    expect(f?.evidence?.some((e) => e.startsWith('advisory:'))).toBe(true)
  })

  it('does not flag curl at or above fixedIn', () => {
    const hits = matchVendorAdvisoriesAgainstApps(
      [app({ name: 'curl', version: '8.4.0', publisher: 'curl' })],
      { catalogPath },
    )
    expect(hits.some((h) => h.cveId === 'CVE-2023-38545')).toBe(false)
  })

  it('does not flag curl before introduced', () => {
    const hits = matchVendorAdvisoriesAgainstApps(
      [app({ name: 'curl', version: '7.68.0', publisher: 'curl' })],
      { catalogPath },
    )
    expect(hits.some((h) => h.cveId === 'CVE-2023-38545')).toBe(false)
  })

  it('handles Ubuntu-style glibc revisions via vulnerableBelow', () => {
    const vulnerable = matchVendorAdvisoriesAgainstApps(
      [app({ name: 'libc6', version: '2.31-0ubuntu9.14' })],
      { catalogPath },
    )
    expect(vulnerable.some((h) => h.cveId === 'CVE-2023-4911')).toBe(true)

    const fixed = matchVendorAdvisoriesAgainstApps(
      [app({ name: 'libc6', version: '2.31-0ubuntu9.15' })],
      { catalogPath },
    )
    expect(fixed.some((h) => h.cveId === 'CVE-2023-4911')).toBe(false)
  })

  it('silences unknown versions rather than guessing', () => {
    const hits = matchVendorAdvisoriesAgainstApps(
      [app({ name: '7-Zip', version: 'unknown' })],
      { catalogPath },
    )
    expect(hits.some((h) => h.cveId === 'CVE-2024-11477')).toBe(false)
  })

  it('loads catalog via default path helper', () => {
    const catalog = loadVendorAdvisoryCatalog(catalogPath)
    expect(catalog.entries.length).toBeGreaterThan(0)
  })
})
