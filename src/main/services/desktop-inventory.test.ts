import { describe, it, expect } from 'vitest'
import { analyzeInstalledApps, buildInventoryPayload, collectDesktopInventory } from './desktop-inventory'
import type { InstalledApp } from '../platform/types'

describe('desktop-inventory', () => {
  it('flags unknown publishers and suspicious names', () => {
    const apps: InstalledApp[] = [
      { name: 'Chrome', version: '1', publisher: 'Google LLC', installDate: '', sizeKb: 1 },
      { name: 'Mystery Tool', version: '1', publisher: '', installDate: '', sizeKb: 1 },
      { name: 'Game Crack Pack', version: '1', publisher: 'Someone', installDate: '', sizeKb: 1 },
    ]
    const findings = analyzeInstalledApps(apps)
    expect(findings.some((f) => f.subjectName === 'Mystery Tool' && f.reason === 'unknown_publisher')).toBe(true)
    expect(findings.some((f) => f.subjectName === 'Game Crack Pack' && f.reason === 'suspicious_app_name')).toBe(true)
    expect(findings.some((f) => f.subjectName === 'Chrome')).toBe(false)
  })

  it('builds a cloud-ready inventory payload', async () => {
    const payload = await collectDesktopInventory({
      platform: 'linux',
      hostname: 'devbox',
      loadApps: async () => [
        { name: 'vim', version: '9', publisher: 'unknown', installDate: '', sizeKb: 10 },
      ],
    })
    expect(payload.count).toBe(1)
    expect(payload.apps[0].name).toBe('vim')
    expect(payload.findings.length).toBeGreaterThanOrEqual(1)
    expect(buildInventoryPayload({
      apps: [],
      platform: 'linux',
      hostname: 'x',
    }).count).toBe(0)
  })
})
