import { describe, it, expect } from 'vitest'
import { DeviceStore } from './store'
import {
  createPairingCode, enrollDevice, listDevices, getDevice, listFindings,
  authenticateDevice, heartbeat, submitInventory, submitFindings,
  getServerKey, issueCommand, requestScan, pollCommands, commandResult,
  getPolicy, putPolicy, isolateDevice, clearIsolation,
  submitNetworkEvents, listNetworkEvents, type SignedRequest,
} from './handlers'
import { generateDeviceKeyPair, signMessage, canonicalRequest, sha256Hex } from './crypto'

function freshStore() {
  let n = 0
  return new DeviceStore({ uuid: () => `id${++n}`, code: () => 'TEST-CODE', now: () => 1_700_000_000_000 })
}

function enrolledDevice(store: DeviceStore) {
  createPairingCode(store)
  const kp = generateDeviceKeyPair()
  const res = enrollDevice(store, { code: 'TEST-CODE', name: 'Laptop', publicKeyPem: kp.publicKeyPem, os: 'linux' })
  return { kp, deviceId: (res.body as { deviceId: string }).deviceId }
}

function signedRequest(kp: { privateKeyPem: string }, deviceId: string, method: string, path: string, body: string, ts: string): SignedRequest {
  const message = canonicalRequest(method, path, ts, sha256Hex(body))
  return {
    method, path, rawBody: body,
    headers: { deviceId, timestamp: ts, signature: signMessage(kp.privateKeyPem, message) },
  }
}

describe('device-api enrollment', () => {
  it('issues a pairing code and enrolls a device that consumes it', () => {
    const store = freshStore()
    const pc = createPairingCode(store)
    expect(pc.status).toBe(201)
    const kp = generateDeviceKeyPair()
    const res = enrollDevice(store, { code: 'TEST-CODE', name: 'TV', publicKeyPem: kp.publicKeyPem })
    expect(res.status).toBe(201)
    expect((res.body as { deviceId: string }).deviceId).toMatch(/^dev_/)
    expect(listDevices(store).body).toMatchObject({ count: 1 })
    const devices = (listDevices(store).body as { devices: Array<{ isolated: boolean; policyVersion: number }> }).devices
    expect(devices[0].isolated).toBe(false)
    expect(devices[0].policyVersion).toBe(1)
  })

  it('rejects enrollment with a bad/missing code', () => {
    const store = freshStore()
    const kp = generateDeviceKeyPair()
    expect(enrollDevice(store, { code: 'NOPE', name: 'x', publicKeyPem: kp.publicKeyPem }).status).toBe(400)
  })

  it('rejects reuse of a pairing code', () => {
    const store = freshStore()
    createPairingCode(store)
    const kp = generateDeviceKeyPair()
    expect(enrollDevice(store, { code: 'TEST-CODE', name: 'a', publicKeyPem: kp.publicKeyPem }).status).toBe(201)
    expect(enrollDevice(store, { code: 'TEST-CODE', name: 'b', publicKeyPem: kp.publicKeyPem }).status).toBe(400)
  })

  it('requires a real public key', () => {
    const store = freshStore()
    createPairingCode(store)
    expect(enrollDevice(store, { code: 'TEST-CODE', name: 'a', publicKeyPem: 'nope' }).status).toBe(400)
  })
})

describe('device-api signature auth', () => {
  const now = 1_700_000_000_000
  const ts = new Date(now).toISOString()

  it('accepts a correctly signed request', () => {
    const store = freshStore()
    const { kp, deviceId } = enrolledDevice(store)
    const path = `/v1/devices/${deviceId}/heartbeat`
    const req = signedRequest(kp, deviceId, 'POST', path, '{}', ts)
    expect(authenticateDevice(store, req, now)).toEqual({ ok: true, deviceId })
  })

  it('rejects a tampered body (hash mismatch)', () => {
    const store = freshStore()
    const { kp, deviceId } = enrolledDevice(store)
    const path = `/v1/devices/${deviceId}/heartbeat`
    const req = signedRequest(kp, deviceId, 'POST', path, '{}', ts)
    req.rawBody = '{"tampered":true}'
    const r = authenticateDevice(store, req, now)
    expect(r.ok).toBe(false)
  })

  it('rejects a stale timestamp', () => {
    const store = freshStore()
    const { kp, deviceId } = enrolledDevice(store)
    const path = `/v1/devices/${deviceId}/heartbeat`
    const req = signedRequest(kp, deviceId, 'POST', path, '{}', ts)
    const r = authenticateDevice(store, req, now + 10 * 60 * 1000) // 10 min later
    expect(r).toMatchObject({ ok: false, status: 401 })
  })

  it('rejects an unknown device and missing headers', () => {
    const store = freshStore()
    expect(authenticateDevice(store, { method: 'POST', path: '/x', rawBody: '{}', headers: {} }, now)).toMatchObject({ ok: false })
    expect(authenticateDevice(store, { method: 'POST', path: '/x', rawBody: '{}', headers: { deviceId: 'dev_nope', timestamp: ts, signature: 'AA==' } }, now)).toMatchObject({ ok: false, error: 'unknown device' })
  })
})

describe('device-api telemetry endpoints', () => {
  const now = 1_700_000_000_000
  it('records heartbeat, inventory, and findings', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    heartbeat(store, deviceId, now)
    submitInventory(store, deviceId, { items: [{}, {}, {}] })
    submitFindings(store, deviceId, { findings: [{ level: 'high', subjectName: 'Sketchy', reason: 'known_c2' }] })

    const d = (getDevice(store, deviceId).body as { lastHeartbeat: string; inventoryCount: number; findingsCount: number })
    expect(d.lastHeartbeat).not.toBeNull()
    expect(d.inventoryCount).toBe(3)
    expect(d.findingsCount).toBe(1)
    expect((listFindings(store).body as { count: number }).count).toBe(1)
  })

  it('does not leak the device public key in detail responses', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    expect((getDevice(store, deviceId).body as Record<string, unknown>).publicKeyPem).toBeUndefined()
  })
})

describe('device-api commands', () => {
  it('enqueues an allowlisted command, polls it, and records a result', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    const issued = issueCommand(store, deviceId, { type: 'RUN_MALWARE_SCAN', parameters: {} })
    expect(issued.status).toBe(201)
    const cmd = (issued.body as { command: { commandId: string; signature: string } }).command
    expect(cmd.signature).toBeTruthy()

    const pending = (pollCommands(store, deviceId).body as { commands: unknown[] }).commands
    expect(pending).toHaveLength(1)

    expect(commandResult(store, deviceId, cmd.commandId, { ok: true, threats: 0 }).status).toBe(202)
    // Once completed it's no longer pending.
    expect((pollCommands(store, deviceId).body as { commands: unknown[] }).commands).toHaveLength(0)
  })

  it('rejects a non-allowlisted command type', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    expect(issueCommand(store, deviceId, { type: 'RUN_SHELL', parameters: {} }).status).toBe(400)
  })

  it('requestScan maps kind to RUN_* commands', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    const health = requestScan(store, deviceId, { kind: 'health' })
    expect(health.status).toBe(201)
    expect((health.body as { command: { type: string } }).command.type).toBe('RUN_HEALTH_ASSESSMENT')
    const malware = requestScan(store, deviceId, { kind: 'malware' })
    expect((malware.body as { command: { type: string; parameters: { scope: string } } }).command.type).toBe('RUN_MALWARE_SCAN')
    expect((malware.body as { command: { parameters: { scope: string } } }).command.parameters.scope).toBe('quick')
    const vuln = requestScan(store, deviceId, { kind: 'vulnerability' })
    expect((vuln.body as { command: { type: string } }).command.type).toBe('RUN_VULNERABILITY_SCAN')
    expect(requestScan(store, deviceId, { kind: 'nope' }).status).toBe(400)
  })

  it('rejects a command for an unknown device', () => {
    const store = freshStore()
    expect(issueCommand(store, 'dev_nope', { type: 'RUN_MALWARE_SCAN' }).status).toBe(404)
  })

  it('rejects a result for an unknown command', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    expect(commandResult(store, deviceId, 'cmd_nope', {}).status).toBe(404)
  })

  it('exposes the server public key for signature verification', () => {
    const store = freshStore()
    expect((getServerKey(store).body as { publicKeyPem: string }).publicKeyPem).toContain('BEGIN PUBLIC KEY')
  })
})

describe('device-api policy + emergency isolate', () => {
  it('returns a default policy and updates it via putPolicy', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    const initial = getPolicy(store, deviceId)
    expect(initial.status).toBe(200)
    expect((initial.body as { policy: { isolated: boolean; version: number } }).policy.isolated).toBe(false)

    const updated = putPolicy(store, deviceId, {
      blockedDomains: ['tracker.malware.test'],
      dnsGuardRequired: true,
    })
    expect(updated.status).toBe(200)
    const body = updated.body as { policy: { version: number; blockedDomains: string[] }; command: { type: string } }
    expect(body.policy.version).toBe(2)
    expect(body.policy.blockedDomains).toEqual(['tracker.malware.test'])
    expect(body.command.type).toBe('APPLY_POLICY')
  })

  it('isolates a device and enqueues ISOLATE_DEVICE', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    const res = isolateDevice(store, deviceId, { reason: 'ransomware suspected' })
    expect(res.status).toBe(202)
    const body = res.body as { policy: { isolated: boolean }; command: { type: string } }
    expect(body.policy.isolated).toBe(true)
    expect(body.command.type).toBe('ISOLATE_DEVICE')
    expect((pollCommands(store, deviceId).body as { commands: unknown[] }).commands.length).toBeGreaterThanOrEqual(1)

    const cleared = clearIsolation(store, deviceId)
    expect(cleared.status).toBe(202)
    expect((cleared.body as { policy: { isolated: boolean } }).policy.isolated).toBe(false)
  })
})

describe('device-api network events', () => {
  it('accepts a batch of events and lists them', () => {
    const store = freshStore()
    const { deviceId } = enrolledDevice(store)
    const res = submitNetworkEvents(store, deviceId, {
      events: [
        { type: 'dns_blocked', subject: 'tracker.malware.test', detail: 'blocked' },
        { type: 'isolation_enabled', subject: 'device' },
      ],
    })
    expect(res.status).toBe(202)
    expect((res.body as { accepted: number }).accepted).toBe(2)
    expect((listNetworkEvents(store, deviceId).body as { count: number }).count).toBe(2)
  })
})
