/**
 * E2E: parent isolate → DeviceCommandAgent.tick → loopback DoT sinkhole →
 * dns_blocked flushed → GET /v1/network-events.
 *
 * Uses an ephemeral control plane + ephemeral DNS port (no system resolv.conf).
 */

import { describe, it, expect, beforeEach, afterEach, afterAll, vi } from 'vitest'
import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import type { AddressInfo } from 'net'
import type { Server } from 'http'

const userData = mkdtempSync(join(tmpdir(), 'bulwark-e2e-'))

vi.mock('electron', () => ({
  app: { getPath: () => userData },
  safeStorage: {
    isEncryptionAvailable: () => false,
    encryptString: (s: string) => Buffer.from(s),
    decryptString: (b: Buffer) => b.toString(),
  },
}))

vi.mock('./logger', () => ({ cloudLog: vi.fn() }))

import { DeviceStore } from '../../cloud/device-api/store'
import { createDeviceApiServer } from '../../cloud/device-api/server'
import { DeviceCommandAgent } from './device-command-agent'
import { devicePolicyEnforcer } from './device-policy-enforcer'
import { dnsResolver } from './dns-resolver'
import { buildDnsQuery, udpQueryDns, aRecordSinkhole } from './dns-query-helper'
import { clearDeviceIdentity } from './device-identity-store'

async function listenEphemeral(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const addr = server.address() as AddressInfo
  return `http://127.0.0.1:${addr.port}`
}

describe('device control plane e2e · isolate → tick → dns_blocked', () => {
  let store: DeviceStore
  let server: Server
  let baseUrl: string
  let agent: DeviceCommandAgent

  beforeEach(async () => {
    store = new DeviceStore()
    server = createDeviceApiServer(store)
    baseUrl = await listenEphemeral(server)
    devicePolicyEnforcer.resetForTest()
    devicePolicyEnforcer.setLocalBlocklistProvider(() => [])
    devicePolicyEnforcer.setResolverStartConfig({ port: 0 as unknown as number })
    await dnsResolver.stop().catch(() => {})
    dnsResolver.setOnBlocked(null)
    dnsResolver.setFilterMode('blocklist', [])
    agent = new DeviceCommandAgent({
      inventorySyncMs: 1e12,
      pollMs: 60_000,
    })
  })

  afterEach(async () => {
    agent.stop()
    await agent.unenroll().catch(() => {})
    clearDeviceIdentity()
    devicePolicyEnforcer.resetForTest()
    await dnsResolver.stop().catch(() => {})
    dnsResolver.setOnBlocked(null)
    dnsResolver.setFilterMode('blocklist', [])
    await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  afterAll(() => {
    try { rmSync(userData, { recursive: true, force: true }) } catch { /* ignore */ }
  })

  it('parent isolate is applied by agent tick and blocked DNS is reported', async () => {
    const boot = await (await fetch(`${baseUrl}/v1/dashboard-bootstrap`)).json() as { token: string }
    expect(boot.token).toBeTruthy()
    const authHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${boot.token}`,
    }

    const pairing = await (await fetch(`${baseUrl}/v1/pairing-codes`, {
      method: 'POST',
      headers: authHeaders,
      body: '{}',
    })).json() as { code: string }
    const enrolled = await agent.enroll({ code: pairing.code, name: 'E2E Laptop', baseUrl })
    expect(enrolled.success).toBe(true)
    if (!enrolled.success) return
    const deviceId = enrolled.deviceId
    // Stop the background poller and wait out the enroll-triggered tick.
    agent.stop()
    await agent.waitForIdle()

    const isolateRes = await fetch(`${baseUrl}/v1/devices/${deviceId}/isolate`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ reason: 'e2e parent isolate' }),
    })
    expect(isolateRes.status).toBe(202)

    // Unauthenticated write/read must fail.
    const denied = await fetch(`${baseUrl}/v1/devices/${deviceId}/isolate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'no token' }),
    })
    expect(denied.status).toBe(401)
    expect((await fetch(`${baseUrl}/v1/devices`)).status).toBe(401)
    expect((await fetch(`${baseUrl}/v1/findings`)).status).toBe(401)
    expect((await fetch(`${baseUrl}/v1/network-events`)).status).toBe(401)

    // First tick: heartbeat, pull isolated policy, execute ISOLATE_DEVICE, start resolver.
    await agent.tick()
    expect(devicePolicyEnforcer.isIsolated()).toBe(true)
    const stats = dnsResolver.getStats()
    expect(stats.running).toBe(true)
    expect(stats.address).toMatch(/^127\.0\.0\.1:\d+$/)
    const port = Number(stats.address!.split(':')[1])

    const blocked = await udpQueryDns(port, buildDnsQuery('evil.not-allowlisted.e2e.test'))
    expect(aRecordSinkhole(blocked)).toEqual([0, 0, 0, 0])

    // Second tick: flush queued dns_blocked (+ isolation_enabled) events.
    await agent.tick()

    const listed = await (await fetch(`${baseUrl}/v1/network-events?deviceId=${encodeURIComponent(deviceId)}`, {
      headers: authHeaders,
    })).json() as {
      events: Array<{ type: string; subject: string | null }>
      count: number
    }
    expect(listed.count).toBeGreaterThanOrEqual(1)
    const types = listed.events.map((e) => e.type)
    expect(types).toContain('dns_blocked')
    expect(types).toContain('isolation_enabled')
    expect(listed.events.some((e) => e.type === 'dns_blocked' && e.subject === 'evil.not-allowlisted.e2e.test')).toBe(true)

    const status = agent.getStatus()
    expect(status.enrolled).toBe(true)
    expect(status.commandsProcessed).toBeGreaterThanOrEqual(1)
  }, 30_000)
})
