import { describe, it, expect } from 'vitest'
import {
  alertToBulwarkEvent,
  networkEventToBulwarkEvent,
  scanHistoryToBulwarkEvent,
} from './activity-adapters'

describe('activity-adapters', () => {
  it('maps kev_finding alerts to vulnerability cards', () => {
    const ev = alertToBulwarkEvent({
      id: 'a1',
      severity: 'high',
      type: 'kev_finding',
      subject: 'curl',
      detail: 'CVE-2023-38545',
      at: '2026-07-28T12:00:00.000Z',
      deviceId: 'dev_1',
      acknowledged: false,
    }, { deviceName: 'Living Room' })

    expect(ev.category).toBe('vulnerability')
    expect(ev.eventType).toBe('vulnerability.detected')
    expect(ev.title).toBe('Vulnerability matched')
    expect(ev.summary).toContain('curl')
    expect(ev.summary).toContain('CVE-2023-38545')
    expect(ev.cause?.confidenceLabel).toBe('highly_likely')
    expect(ev.remediation?.nextStep).toMatch(/Findings/i)
    expect(ev.source.deviceName).toBe('Living Room')
  })

  it('maps isolation alerts to policy cards', () => {
    const ev = alertToBulwarkEvent({
      id: 'a2',
      severity: 'high',
      type: 'isolation',
      subject: 'dev_1',
      at: '2026-07-28T12:00:00.000Z',
      deviceId: 'dev_1',
      acknowledged: false,
    })
    expect(ev.eventType).toBe('policy.isolation.enabled')
    expect(ev.status).toBe('blocked')
    expect(ev.remediation?.reversible).toBe(true)
  })

  it('maps dns_blocked network events', () => {
    const ev = networkEventToBulwarkEvent({
      id: 'n1',
      deviceId: 'dev_1',
      type: 'dns_blocked',
      at: '2026-07-28T12:00:00.000Z',
      subject: 'malware.test',
      detail: 'urhaus',
    })
    expect(ev.eventType).toBe('network.connection.blocked')
    expect(ev.title).toBe('Threat blocked')
    expect(ev.evidence.some((e) => e.value === 'malware.test')).toBe(true)
  })

  it('maps scan history into cleaning activity cards', () => {
    const ev = scanHistoryToBulwarkEvent({
      id: 'h1',
      type: 'cleaner',
      timestamp: '2026-07-28T12:00:00.000Z',
      duration: 1200,
      totalItemsFound: 40,
      totalItemsCleaned: 12,
      totalItemsSkipped: 3,
      totalSpaceSaved: 5 * 1024 * 1024,
      errorCount: 0,
    })
    expect(ev.category).toBe('cleaning')
    expect(ev.status).toBe('success')
    expect(ev.summary).toContain('12')
    expect(ev.summary).toMatch(/5 MB/)
    expect(ev.cause?.confidenceLabel).toBe('confirmed')
  })

  it('flags scan history errors as warnings', () => {
    const ev = scanHistoryToBulwarkEvent({
      id: 'h2',
      type: 'malware',
      timestamp: '2026-07-28T12:00:00.000Z',
      duration: 100,
      totalItemsFound: 1,
      totalItemsCleaned: 0,
      totalItemsSkipped: 1,
      totalSpaceSaved: 0,
      errorCount: 2,
      scheduled: true,
      scheduleName: 'Nightly',
    })
    expect(ev.category).toBe('security')
    expect(ev.status).toBe('warning')
    expect(ev.cause?.summary).toContain('Nightly')
  })
})
