import { describe, it, expect, vi } from 'vitest'
import type { InstalledApp } from '../platform/types'
import {
  runHealthAssessment,
  runMalwareScanQuick,
  runVulnerabilityScanPosture,
  scanKindToCommandType,
  executeRemoteScan,
} from './desktop-remote-scans'

function app(overrides: Partial<InstalledApp> = {}): InstalledApp {
  return {
    name: 'Normal App',
    version: '1.0',
    publisher: 'Microsoft Corporation',
    installDate: '2020-01-01',
    sizeKb: 100,
    ...overrides,
  }
}

describe('desktop-remote-scans', () => {
  it('maps scan kinds to allowlisted command types', () => {
    expect(scanKindToCommandType('health')).toBe('RUN_HEALTH_ASSESSMENT')
    expect(scanKindToCommandType('malware')).toBe('RUN_MALWARE_SCAN')
    expect(scanKindToCommandType('lolbins')).toBe('RUN_MALWARE_SCAN')
    expect(scanKindToCommandType('vulnerability')).toBe('RUN_VULNERABILITY_SCAN')
    expect(scanKindToCommandType('nope')).toBeNull()
  })

  it('health assessment is not a stub and includes posture score', () => {
    const r = runHealthAssessment([
      app(),
      app({ name: 'Mystery', publisher: '' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.ok).toBe(true)
    expect(typeof r.postureScore).toBe('number')
    expect(r.findings).toBeGreaterThan(0)
    expect(r._findings.some((f) => f.subjectName === 'device_posture')).toBe(true)
  })

  it('quick malware scan flags suspicious app names', async () => {
    const r = await runMalwareScanQuick([
      app({ name: 'TotallyLegit keygen Tool', publisher: 'Unknown' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.threatsFound).toBeGreaterThan(0)
    expect(r._findings.some((f) => f.reason === 'suspicious_app_name')).toBe(true)
    expect(r.note).toMatch(/LotL|technique grep/i)
  })

  it('vulnerability posture scan returns risk findings without stubbing', async () => {
    const r = await runVulnerabilityScanPosture([
      app({ name: 'Sketchy', publisher: '' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.note).toMatch(/KEV|NVD/i)
    expect(r.appsAssessed).toBe(1)
  })

  it('vulnerability scan emits KEV CVE findings for vulnerable curl', async () => {
    const r = await runVulnerabilityScanPosture([
      app({ name: 'curl', version: '7.88.1', publisher: 'curl' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.scope).toMatch(/kev/)
    expect(r._findings.some((f) => f.category === 'kev' && f.subjectName === 'CVE-2023-38545')).toBe(true)
    expect(r.note).toMatch(/NVD|incomplete/i)
  })

  it('vulnerability scan can attach EPSS tags when epss=true', async () => {
    const prevFetch = globalThis.fetch
    globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
      const u = String(url)
      if (u.includes('epss')) {
        return {
          ok: true,
          json: async () => ({
            data: [{ cve: 'CVE-2023-38545', epss: '0.78', percentile: '0.99' }],
          }),
        } as Response
      }
      throw new Error(`unexpected fetch ${u}`)
    }) as typeof fetch
    try {
      const r = await runVulnerabilityScanPosture(
        [app({ name: 'curl', version: '7.88.1', publisher: 'curl' })],
        { epss: true },
      )
      expect(r.scope).toMatch(/epss/)
      const hit = r._findings.find((f) => f.subjectName === 'CVE-2023-38545')
      expect(hit?.reason).toMatch(/epss=/)
    } finally {
      globalThis.fetch = prevFetch
    }
  })


  it('executeRemoteScan dispatches by type', async () => {
    const apps = [app()]
    expect((await executeRemoteScan('RUN_HEALTH_ASSESSMENT', apps)).type).toBe('RUN_HEALTH_ASSESSMENT')
    expect((await executeRemoteScan('RUN_MALWARE_SCAN', apps, { scope: 'quick' })).scope).toBe('quick')
    expect((await executeRemoteScan('RUN_VULNERABILITY_SCAN', apps)).type).toBe('RUN_VULNERABILITY_SCAN')
  }, 15_000)
})
