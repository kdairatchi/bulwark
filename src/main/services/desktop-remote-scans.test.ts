import { describe, it, expect } from 'vitest'
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

  it('quick malware scan flags suspicious app names', () => {
    const r = runMalwareScanQuick([
      app({ name: 'TotallyLegit keygen Tool', publisher: 'Unknown' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.threatsFound).toBeGreaterThan(0)
    expect(r._findings.some((f) => f.reason === 'suspicious_app_name')).toBe(true)
  })

  it('vulnerability posture scan returns risk findings without stubbing', () => {
    const r = runVulnerabilityScanPosture([
      app({ name: 'Sketchy', publisher: '' }),
    ])
    expect(r.stub).toBe(false)
    expect(r.note).toMatch(/Phase 5/)
    expect(r.appsAssessed).toBe(1)
  })

  it('executeRemoteScan dispatches by type', () => {
    const apps = [app()]
    expect(executeRemoteScan('RUN_HEALTH_ASSESSMENT', apps).type).toBe('RUN_HEALTH_ASSESSMENT')
    expect(executeRemoteScan('RUN_MALWARE_SCAN', apps, { scope: 'quick' }).scope).toBe('quick')
    expect(executeRemoteScan('RUN_VULNERABILITY_SCAN', apps).type).toBe('RUN_VULNERABILITY_SCAN')
  })
})
