import { describe, it, expect, afterEach } from 'vitest'
import type { Server } from 'http'
import { AddressInfo } from 'net'
import { DeviceStore } from './store'
import {
  createPairingCode, enrollDevice, submitFindings, submitNetworkEvents,
  isolateDevice, heartbeat, getFleetReport, listAlerts, createBreachMonitor,
} from './handlers'
import { createHibpClient } from './hibp-client'
import { createDeviceApiServer } from './server'
import { generateDeviceKeyPair } from './crypto'

const NOW = 1_700_000_000_000

function freshStore(now = NOW) {
  let n = 0
  return new DeviceStore({
    uuid: () => `id${++n}`,
    code: () => 'TEST-CODE',
    now: () => now,
  })
}

function enroll(store: DeviceStore, name = 'Laptop', os = 'linux') {
  createPairingCode(store)
  const kp = generateDeviceKeyPair()
  const res = enrollDevice(store, {
    code: 'TEST-CODE',
    name,
    publicKeyPem: kp.publicKeyPem,
    os,
  })
  return { kp, deviceId: (res.body as { deviceId: string }).deviceId }
}

describe('getFleetReport', () => {
  it('returns empty-fleet defaults', () => {
    const store = freshStore()
    const res = getFleetReport(store)
    expect(res.status).toBe(200)
    const body = res.body as {
      generatedAt: string
      summary: {
        deviceCount: number
        onlineCount: number
        avgSecurityScore: number
        worstSecurityScore: number
        openFindingsTotal: number
        openKevTotal: number
        isolatedCount: number
        dnsBlockedRecent: number
        unackedBreaches: number
      }
      devices: unknown[]
      count: number
    }
    expect(body.generatedAt).toBe(new Date(NOW).toISOString())
    expect(body.summary).toEqual({
      deviceCount: 0,
      onlineCount: 0,
      avgSecurityScore: 0,
      worstSecurityScore: 100,
      openFindingsTotal: 0,
      openKevTotal: 0,
      isolatedCount: 0,
      dnsBlockedRecent: 0,
      unackedBreaches: 0,
    })
    expect(body.devices).toEqual([])
    expect(body.count).toBe(0)
  })

  it('summarizes enrolled device with KEV, isolation, dns, and breaches', async () => {
    const store = freshStore()
    const { deviceId } = enroll(store)
    heartbeat(store, deviceId, NOW)

    submitFindings(store, deviceId, {
      findings: [{
        level: 'likely_affected',
        subjectName: 'Chrome',
        reason: 'CISA KEV CVE-2024-1234',
        category: 'kev',
        fixRecommendation: 'Upgrade Chrome',
      }],
    })
    isolateDevice(store, deviceId, { reason: 'test' })
    submitNetworkEvents(store, deviceId, {
      events: [
        { type: 'dns_blocked', subject: 'evil.test', detail: 'blocked' },
        { type: 'dns_blocked', subject: 'ads.test', detail: 'blocked' },
        { type: 'dns_query', subject: 'ok.test' },
      ],
    })
    await createBreachMonitor(store, { email: 'pwned@hibp-test.bulwark.local' }, createHibpClient({ stub: true }))

    const res = getFleetReport(store)
    expect(res.status).toBe(200)
    const body = res.body as {
      summary: Record<string, number>
      devices: Array<{
        id: string
        openFindingsCount: number
        openKevCount: number
        isolated: boolean
        dnsBlockedCount: number
        securityScore: number
      }>
      count: number
    }
    expect(body.count).toBe(1)
    expect(body.summary.deviceCount).toBe(1)
    expect(body.summary.onlineCount).toBe(1)
    expect(body.summary.openFindingsTotal).toBe(1)
    expect(body.summary.openKevTotal).toBe(1)
    expect(body.summary.isolatedCount).toBe(1)
    expect(body.summary.dnsBlockedRecent).toBe(2)
    expect(body.summary.unackedBreaches).toBeGreaterThanOrEqual(1)
    expect(body.summary.avgSecurityScore).toBe(body.devices[0].securityScore)
    expect(body.summary.worstSecurityScore).toBe(body.devices[0].securityScore)
    expect(body.devices[0]).toMatchObject({
      id: deviceId,
      openFindingsCount: 1,
      openKevCount: 1,
      isolated: true,
      dnsBlockedCount: 2,
    })
    expect(body.devices[0].securityScore).toBeLessThan(100)
  })
})

describe('listAlerts', () => {
  it('materializes kev, isolation, dns_blocked, and breach alerts', async () => {
    const store = freshStore()
    const { deviceId } = enroll(store)
    submitFindings(store, deviceId, {
      findings: [{
        level: 'likely_affected',
        subjectName: 'Chrome',
        reason: 'KEV hit',
        category: 'kev',
      }],
    })
    isolateDevice(store, deviceId, { reason: 'compromise' })
    submitNetworkEvents(store, deviceId, {
      events: [
        { type: 'dns_blocked', subject: 'tracker.evil', detail: 'blocked' },
        { type: 'dns_blocked', subject: 'tracker.evil', detail: 'dup subject' },
      ],
    })
    await createBreachMonitor(store, { email: 'pwned@example.com' }, createHibpClient({ stub: true }))

    const res = listAlerts(store)
    expect(res.status).toBe(200)
    const body = res.body as {
      alerts: Array<{ id: string; type: string; severity: string; deviceId: string | null; acknowledged: boolean }>
      count: number
    }
    const types = new Set(body.alerts.map((a) => a.type))
    expect(types.has('kev_finding')).toBe(true)
    expect(types.has('isolation')).toBe(true)
    expect(types.has('dns_blocked')).toBe(true)
    expect(types.has('breach')).toBe(true)

    const kev = body.alerts.find((a) => a.type === 'kev_finding')!
    expect(kev.id).toMatch(/^alert_kev_/)
    expect(kev.severity).toBe('critical')
    expect(kev.deviceId).toBe(deviceId)
    expect(kev.acknowledged).toBe(false)

    const iso = body.alerts.find((a) => a.type === 'isolation')!
    expect(iso.id).toBe(`alert_isolation_${deviceId}`)
    expect(iso.severity).toBe('high')

    const dns = body.alerts.filter((a) => a.type === 'dns_blocked')
    expect(dns).toHaveLength(1) // deduped by deviceId+subject
    expect(dns[0].id).toMatch(/^alert_dns_/)
    expect(dns[0].severity).toBe('medium')

    const breach = body.alerts.find((a) => a.type === 'breach')!
    expect(breach.id).toMatch(/^alert_breach_/)
    expect(breach.deviceId).toBeNull()
    expect(breach.severity).toBe('high')
  })

  it('filters alerts by deviceId (excludes account breaches)', async () => {
    let codeN = 0
    const multi = new DeviceStore({
      uuid: (() => { let i = 0; return () => `id${++i}` })(),
      code: () => `CODE-${++codeN}`,
      now: () => NOW,
    })
    createPairingCode(multi)
    const kp1 = generateDeviceKeyPair()
    const e1 = enrollDevice(multi, { code: 'CODE-1', name: 'One', publicKeyPem: kp1.publicKeyPem, os: 'linux' })
    const id1 = (e1.body as { deviceId: string }).deviceId
    createPairingCode(multi)
    const kp2 = generateDeviceKeyPair()
    const e2 = enrollDevice(multi, { code: 'CODE-2', name: 'Two', publicKeyPem: kp2.publicKeyPem, os: 'linux' })
    const id2 = (e2.body as { deviceId: string }).deviceId

    submitFindings(multi, id1, {
      findings: [{ level: 'high', subjectName: 'App1', reason: 'kev', category: 'kev' }],
    })
    submitFindings(multi, id2, {
      findings: [{ level: 'high', subjectName: 'App2', reason: 'kev', category: 'cve' }],
    })
    isolateDevice(multi, id2, {})
    await createBreachMonitor(multi, { email: 'pwned@example.com' }, createHibpClient({ stub: true }))

    const filtered = listAlerts(multi, { deviceId: id1 })
    const body = filtered.body as { alerts: Array<{ type: string; deviceId: string | null }> }
    expect(body.alerts.every((a) => a.deviceId === id1)).toBe(true)
    expect(body.alerts.some((a) => a.type === 'kev_finding')).toBe(true)
    expect(body.alerts.some((a) => a.type === 'breach')).toBe(false)
    expect(body.alerts.some((a) => a.type === 'isolation')).toBe(false)
  })

  it('respects limit cap', () => {
    const store = freshStore()
    const { deviceId } = enroll(store)
    const events = Array.from({ length: 10 }, (_, i) => ({
      type: 'dns_blocked',
      subject: `host${i}.test`,
      detail: 'blocked',
    }))
    submitNetworkEvents(store, deviceId, { events })
    const res = listAlerts(store, { limit: 3 })
    const body = res.body as { alerts: unknown[]; count: number }
    expect(body.count).toBe(3)
    expect(body.alerts).toHaveLength(3)
  })
})

describe('reports/alerts HTTP routes', () => {
  let server: Server | null = null

  afterEach(async () => {
    if (!server) return
    await new Promise<void>((resolve) => server!.close(() => resolve()))
    server = null
  })

  it('requires Bearer and returns report + alerts', async () => {
    const store = new DeviceStore({
      dashboardToken: 'report-secret',
      allowDashboardBootstrap: false,
      uuid: (() => { let n = 0; return () => `id${++n}` })(),
      code: () => 'ABCD-1234',
      now: () => NOW,
    })
    createPairingCode(store)
    const kp = generateDeviceKeyPair()
    enrollDevice(store, { code: 'ABCD-1234', name: 'TV', publicKeyPem: kp.publicKeyPem, os: 'linux' })

    server = createDeviceApiServer(store, { hibp: createHibpClient({ stub: true }) })
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()))
    const port = (server.address() as AddressInfo).port
    const base = `http://127.0.0.1:${port}`

    expect((await fetch(`${base}/v1/reports`)).status).toBe(401)
    expect((await fetch(`${base}/v1/alerts`)).status).toBe(401)

    const auth = { Authorization: 'Bearer report-secret' }
    const report = await (await fetch(`${base}/v1/reports`, { headers: auth })).json() as {
      summary: { deviceCount: number }
      count: number
    }
    expect(report.summary.deviceCount).toBe(1)
    expect(report.count).toBe(1)

    const alerts = await (await fetch(`${base}/v1/alerts?limit=10`, { headers: auth })).json() as {
      alerts: unknown[]
      count: number
    }
    expect(alerts.count).toBe(alerts.alerts.length)
  })
})
