// Pure request handlers + device signature auth. No I/O — the http server in
// server.ts adapts Node requests to these, which keeps them unit-testable.

import { DeviceStore } from './store'
import { canonicalRequest, sha256Hex, verifyMessage } from './crypto'

export interface HandlerResult {
  status: number
  body: unknown
}

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000

// ─── Public endpoints ───────────────────────────────────────

export function createPairingCode(store: DeviceStore): HandlerResult {
  const pc = store.createPairingCode()
  return { status: 201, body: { code: pc.code, expiresAt: new Date(pc.expiresAt).toISOString() } }
}

/** Extract Bearer token from an Authorization header value. */
export function parseBearerToken(authorization: string | undefined | null): string | null {
  if (!authorization) return null
  const m = authorization.trim().match(/^Bearer\s+(.+)$/i)
  return m ? m[1].trim() : null
}

export type DashboardAuthResult =
  | { ok: true }
  | { ok: false; status: number; error: string }

/** Require Authorization: Bearer <dashboard-token> for parent write routes. */
export function authenticateDashboard(
  store: DeviceStore,
  authorization: string | undefined | null,
): DashboardAuthResult {
  const token = parseBearerToken(authorization)
  if (!token) return { ok: false, status: 401, error: 'missing dashboard bearer token' }
  if (!store.verifyDashboardToken(token)) {
    return { ok: false, status: 401, error: 'invalid dashboard token' }
  }
  return { ok: true }
}

/**
 * Local/dev helper: return the dashboard token when bootstrap is allowed
 * (auto-generated token, not a production DASHBOARD_TOKEN env).
 */
export function dashboardBootstrap(store: DeviceStore): HandlerResult {
  if (!store.canBootstrapDashboard()) {
    return { status: 403, body: { error: 'dashboard bootstrap disabled' } }
  }
  return {
    status: 200,
    body: {
      token: store.dashboardToken(),
      tokenType: 'Bearer',
      note: 'Local/dev only — set DASHBOARD_TOKEN to disable bootstrap',
    },
  }
}

export function enrollDevice(store: DeviceStore, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const code = typeof o.code === 'string' ? o.code.trim().toUpperCase() : ''
  const name = typeof o.name === 'string' && o.name.trim() ? o.name.trim() : ''
  const publicKeyPem = typeof o.publicKeyPem === 'string' ? o.publicKeyPem : ''
  const os = typeof o.os === 'string' ? o.os : null
  if (!code || !name || !publicKeyPem.includes('BEGIN PUBLIC KEY')) {
    return { status: 400, body: { error: 'code, name, and publicKeyPem are required' } }
  }
  if (!store.consumePairingCode(code)) {
    return { status: 400, body: { error: 'invalid, used, or expired pairing code' } }
  }
  const device = store.enrollDevice({ name, publicKeyPem, os })
  return { status: 201, body: { deviceId: device.id, enrolledAt: device.enrolledAt } }
}

export function listDevices(store: DeviceStore): HandlerResult {
  const devices = store.listDevices().map((d) => {
    const policy = store.getPolicy(d.id)
    return {
      id: d.id, name: d.name, os: d.os, enrolledAt: d.enrolledAt,
      lastHeartbeat: d.lastHeartbeat, inventoryCount: d.inventoryCount, findingsCount: d.findingsCount,
      isolated: policy?.isolated ?? false,
      policyVersion: policy?.version ?? 1,
      dnsGuardRequired: policy?.dnsGuardRequired ?? false,
      blockedDomains: policy?.blockedDomains ?? [],
    }
  })
  return { status: 200, body: { devices, count: devices.length } }
}

export function getDevice(store: DeviceStore, id: string): HandlerResult {
  const d = store.getDevice(id)
  if (!d) return { status: 404, body: { error: 'device not found' } }
  return { status: 200, body: { ...d, publicKeyPem: undefined } }
}

export function listFindings(store: DeviceStore, deviceId?: string): HandlerResult {
  const findings = store.listFindings(deviceId)
  return { status: 200, body: { findings, count: findings.length } }
}

// ─── Device signature auth ──────────────────────────────────

export interface SignedRequest {
  method: string
  path: string
  rawBody: string
  headers: { deviceId?: string; timestamp?: string; signature?: string }
}

export type AuthResult = { ok: true; deviceId: string } | { ok: false; status: number; error: string }

/**
 * Verify a device-signed request: the device must exist, the timestamp must be
 * fresh (replay window), and the Ed25519 signature must validate over the
 * canonical (method, path, timestamp, body-hash) string using the stored key.
 */
export function authenticateDevice(store: DeviceStore, req: SignedRequest, now: number): AuthResult {
  const { deviceId, timestamp, signature } = req.headers
  if (!deviceId || !timestamp || !signature) {
    return { ok: false, status: 401, error: 'missing device auth headers' }
  }
  const device = store.getDevice(deviceId)
  if (!device) return { ok: false, status: 401, error: 'unknown device' }

  const ts = Date.parse(timestamp)
  if (Number.isNaN(ts) || Math.abs(now - ts) > MAX_CLOCK_SKEW_MS) {
    return { ok: false, status: 401, error: 'stale or invalid timestamp' }
  }
  const message = canonicalRequest(req.method, req.path, timestamp, sha256Hex(req.rawBody))
  if (!verifyMessage(device.publicKeyPem, message, signature)) {
    return { ok: false, status: 401, error: 'invalid signature' }
  }
  return { ok: true, deviceId }
}

// ─── Authenticated device endpoints ─────────────────────────

export function heartbeat(store: DeviceStore, deviceId: string, now: number): HandlerResult {
  store.recordHeartbeat(deviceId)
  return { status: 200, body: { ok: true, serverTime: new Date(now).toISOString(), nextCheckInSec: 60 } }
}

export function submitInventory(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const items = Array.isArray(o.items) ? o.items : Array.isArray(o.apps) ? o.apps : []
  const count = typeof o.count === 'number' ? o.count : items.length
  store.addInventory(deviceId, count)
  return { status: 202, body: { accepted: count } }
}

export function getServerKey(store: DeviceStore): HandlerResult {
  return { status: 200, body: { publicKeyPem: store.serverPublicKey() } }
}

/** Dashboard side: enqueue an allowlisted, signed command for a device. */
export function issueCommand(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const type = typeof o.type === 'string' ? o.type : ''
  const parameters = (o.parameters && typeof o.parameters === 'object') ? o.parameters as Record<string, unknown> : {}
  if (!store.getDevice(deviceId)) return { status: 404, body: { error: 'device not found' } }
  const envelope = store.issueCommand(deviceId, type, parameters)
  if (!envelope) return { status: 400, body: { error: `command type not allowed: ${type}` } }
  return { status: 201, body: { command: envelope } }
}

/** Device side: fetch pending signed commands (device verifies them locally). */
export function pollCommands(store: DeviceStore, deviceId: string): HandlerResult {
  return { status: 200, body: { commands: store.pendingCommands(deviceId) } }
}

export function commandResult(store: DeviceStore, deviceId: string, commandId: string, input: unknown): HandlerResult {
  const ok = store.recordCommandResult(deviceId, commandId, (input ?? {}) as Record<string, unknown>)
  if (!ok) return { status: 404, body: { error: 'unknown command for this device' } }
  return { status: 202, body: { accepted: true } }
}

export function submitFindings(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const raw = Array.isArray(o.findings) ? o.findings : []
  const findings = raw.map((f) => {
    const r = (f ?? {}) as Record<string, unknown>
    return {
      level: typeof r.level === 'string' ? r.level : 'unknown',
      subjectName: typeof r.subjectName === 'string' ? r.subjectName : 'unknown',
      reason: typeof r.reason === 'string' ? r.reason : '',
    }
  })
  const accepted = store.addFindings(deviceId, findings)
  return { status: 202, body: { accepted } }
}

export function getPolicy(store: DeviceStore, deviceId: string): HandlerResult {
  const policy = store.getPolicy(deviceId)
  if (!policy) return { status: 404, body: { error: 'device not found' } }
  return { status: 200, body: { policy } }
}

/** Dashboard: replace/merge policy fields (does not auto-enqueue APPLY_POLICY). */
export function putPolicy(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  if (!store.getDevice(deviceId)) return { status: 404, body: { error: 'device not found' } }
  const o = (input ?? {}) as Record<string, unknown>
  const patch: Record<string, unknown> = {}
  if (typeof o.isolated === 'boolean') patch.isolated = o.isolated
  if (typeof o.dnsGuardRequired === 'boolean') patch.dnsGuardRequired = o.dnsGuardRequired
  if (typeof o.allowInstallUnknown === 'boolean') patch.allowInstallUnknown = o.allowInstallUnknown
  if (Array.isArray(o.blockedDomains)) {
    patch.blockedDomains = o.blockedDomains.filter((d): d is string => typeof d === 'string')
  }
  if (Array.isArray(o.isolationAllowlist)) {
    patch.isolationAllowlist = o.isolationAllowlist.filter((d): d is string => typeof d === 'string')
  }
  const policy = store.updatePolicy(deviceId, patch as Parameters<DeviceStore['updatePolicy']>[1])
  // Also enqueue APPLY_POLICY so online agents pick it up quickly.
  const command = store.issueCommand(deviceId, 'APPLY_POLICY', { version: policy!.version })
  return { status: 200, body: { policy, command } }
}

export function isolateDevice(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const reason = typeof o.reason === 'string' ? o.reason : undefined
  const result = store.isolateDevice(deviceId, reason)
  if (!result) return { status: 404, body: { error: 'device not found' } }
  return { status: 202, body: result }
}

export function clearIsolation(store: DeviceStore, deviceId: string): HandlerResult {
  const result = store.clearIsolation(deviceId)
  if (!result) return { status: 404, body: { error: 'device not found' } }
  return { status: 202, body: result }
}

export function submitNetworkEvents(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const raw = Array.isArray(o.events) ? o.events : []
  const events = raw.map((e) => {
    const r = (e ?? {}) as Record<string, unknown>
    return {
      type: typeof r.type === 'string' ? r.type : '',
      at: typeof r.at === 'string' ? r.at : undefined,
      subject: typeof r.subject === 'string' ? r.subject : null,
      detail: typeof r.detail === 'string' ? r.detail : null,
      metadata: (r.metadata && typeof r.metadata === 'object') ? r.metadata as Record<string, unknown> : {},
    }
  })
  const accepted = store.addNetworkEvents(deviceId, events)
  return { status: 202, body: { accepted } }
}

export function listNetworkEvents(store: DeviceStore, deviceId?: string): HandlerResult {
  const events = store.listNetworkEvents(deviceId)
  return { status: 200, body: { events, count: events.length } }
}
