import { describe, it, expect, afterEach } from 'vitest'
import type { Server } from 'http'
import { AddressInfo } from 'net'
import { DeviceStore } from './store'
import { createDeviceApiServer } from './server'
import { createPairingCode, enrollDevice, submitFindings } from './handlers'
import { generateDeviceKeyPair } from './crypto'

describe('dashboard read auth (HTTP)', () => {
  let server: Server | null = null

  afterEach(async () => {
    if (!server) return
    await new Promise<void>((resolve) => server!.close(() => resolve()))
    server = null
  })

  async function start(): Promise<{ base: string; store: DeviceStore; token: string }> {
    const store = new DeviceStore({
      dashboardToken: 'read-secret',
      allowDashboardBootstrap: false,
      uuid: (() => { let n = 0; return () => `id${++n}` })(),
      code: () => 'ABCD-1234',
      now: () => 1_700_000_000_000,
    })
    createPairingCode(store)
    const kp = generateDeviceKeyPair()
    enrollDevice(store, {
      code: 'ABCD-1234',
      name: 'TV',
      publicKeyPem: kp.publicKeyPem,
      os: 'linux',
    })
    const deviceId = store.listDevices()[0].id
    submitFindings(store, deviceId, {
      findings: [{ level: 'potential_match', subjectName: 'X', reason: 'unknown_publisher' }],
    })

    server = createDeviceApiServer(store)
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()))
    const port = (server.address() as AddressInfo).port
    return { base: `http://127.0.0.1:${port}`, store, token: 'read-secret' }
  }

  it('rejects unauthenticated dashboard reads and accepts Bearer', async () => {
    const { base, token } = await start()
    for (const path of ['/v1/devices', '/v1/findings', '/v1/network-events']) {
      expect((await fetch(`${base}${path}`)).status).toBe(401)
    }
    const auth = { Authorization: `Bearer ${token}` }
    const devices = await (await fetch(`${base}/v1/devices`, { headers: auth })).json() as {
      devices: Array<{ id: string; securityScore: number }>
    }
    expect(devices.devices).toHaveLength(1)
    expect(devices.devices[0].securityScore).toBeLessThan(100)

    const findings = await (await fetch(`${base}/v1/findings`, { headers: auth })).json() as { count: number }
    expect(findings.count).toBe(1)

    // Public exceptions remain open.
    expect((await fetch(`${base}/v1/server-key`)).status).toBe(200)
    expect((await fetch(`${base}/v1/dashboard-bootstrap`)).status).toBe(403)
  })
})
