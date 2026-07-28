// Pure request handlers + device signature auth. No I/O — the http server in
// server.ts adapts Node requests to these, which keeps them unit-testable.

import { DeviceStore, isFindingStatus, type StoredFindingStatus, BREACH_MONITOR_LIMIT } from './store'
import { canonicalRequest, sha256Hex, verifyMessage } from './crypto'
import type { HibpClient, HibpBreach } from './hibp-client'
import { normalizeEmail } from './hibp-client'

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

function deviceDashboardView(store: DeviceStore, d: NonNullable<ReturnType<DeviceStore['getDevice']>>) {
  const policy = store.getPolicy(d.id)
  const agent = d.agentStatus
  const isolated = policy?.isolated ?? false
  // Only surface VPN pending when the agent has reported DNS Guard status (TV).
  const dnsGuardRunning = agent?.dnsGuardRunning ?? null
  const vpnConsentPending = agent
    ? (agent.vpnConsentPending || (isolated && !agent.dnsGuardRunning))
    : false
  return {
    id: d.id, name: d.name, os: d.os, enrolledAt: d.enrolledAt,
    lastHeartbeat: d.lastHeartbeat, inventoryCount: d.inventoryCount, findingsCount: d.findingsCount,
    openFindingsCount: store.openFindings(d.id).length,
    securityScore: store.securityScore(d.id),
    isolated,
    policyVersion: policy?.version ?? 1,
    dnsGuardRequired: policy?.dnsGuardRequired ?? false,
    blockedDomains: policy?.blockedDomains ?? [],
    dnsGuardRunning,
    vpnConsentPending,
    agentStatus: agent,
  }
}

export function listDevices(store: DeviceStore): HandlerResult {
  const devices = store.listDevices().map((d) => deviceDashboardView(store, d))
  return { status: 200, body: { devices, count: devices.length } }
}

export function getDevice(store: DeviceStore, id: string): HandlerResult {
  const d = store.getDevice(id)
  if (!d) return { status: 404, body: { error: 'device not found' } }
  return { status: 200, body: { ...deviceDashboardView(store, d), publicKeyPem: undefined } }
}

export function listFindings(store: DeviceStore, deviceId?: string): HandlerResult {
  const findings = store.listFindings(deviceId)
  return { status: 200, body: { findings, count: findings.length } }
}

/** Dashboard: mark a finding reviewed (false_positive, accepted_risk, etc.). */
export function reviewFinding(store: DeviceStore, findingId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const statusRaw = typeof o.status === 'string' ? o.status.trim() : ''
  if (!isFindingStatus(statusRaw)) {
    return { status: 400, body: { error: 'status must be a valid finding status' } }
  }
  const note = typeof o.note === 'string' ? o.note : typeof o.reviewNote === 'string' ? o.reviewNote : null
  const finding = store.reviewFinding(findingId, statusRaw as StoredFindingStatus, note)
  if (!finding) return { status: 404, body: { error: 'finding not found' } }
  const score = store.securityScore(finding.deviceId)
  return {
    status: 200,
    body: {
      finding,
      securityScore: score,
      openFindingsCount: store.openFindings(finding.deviceId).length,
    },
  }
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
  const dns = (o.dnsGuard && typeof o.dnsGuard === 'object')
    ? o.dnsGuard as Record<string, unknown>
    : null
  const agentStatus = dns ? {
    dnsGuardRunning: dns.running === true,
    vpnConsentPending: dns.vpnConsentPending === true,
    isolatedReported: dns.isolated === true,
    filterMode: typeof dns.mode === 'string' ? dns.mode : null,
  } : null
  store.addInventory(deviceId, count, agentStatus)
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

/**
 * Dashboard sugar: POST /v1/devices/{id}/scan
 * Maps kind → RUN_HEALTH_ASSESSMENT | RUN_MALWARE_SCAN | RUN_VULNERABILITY_SCAN.
 */
export function requestScan(store: DeviceStore, deviceId: string, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const kind = typeof o.kind === 'string' ? o.kind : typeof o.type === 'string' ? o.type : ''
  const parameters = (o.parameters && typeof o.parameters === 'object')
    ? { ...(o.parameters as Record<string, unknown>) }
    : {}
  if (typeof o.scope === 'string' && parameters.scope === undefined) {
    parameters.scope = o.scope
  }
  for (const key of ['kevSync', 'syncKev', 'osv', 'epss'] as const) {
    if (o[key] !== undefined && parameters[key] === undefined) {
      parameters[key] = o[key]
    }
  }
  const type = (() => {
    switch (kind.trim().toLowerCase()) {
      case 'health':
      case 'health_assessment':
      case 'run_health_assessment':
        return 'RUN_HEALTH_ASSESSMENT'
      case 'malware':
      case 'malware_scan':
      case 'run_malware_scan':
        if (parameters.scope === undefined) parameters.scope = 'quick'
        return 'RUN_MALWARE_SCAN'
      case 'lolbins':
      case 'lotl':
        if (parameters.scope === undefined) parameters.scope = 'lolbins'
        return 'RUN_MALWARE_SCAN'
      case 'vulnerability':
      case 'vuln':
      case 'vulnerability_scan':
      case 'run_vulnerability_scan':
        return 'RUN_VULNERABILITY_SCAN'
      default:
        return null
    }
  })()
  if (!type) {
    return {
      status: 400,
      body: { error: 'kind must be health, malware, vulnerability, or lolbins' },
    }
  }
  return issueCommand(store, deviceId, { type, parameters })
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
      status: typeof r.status === 'string' ? r.status : undefined,
      category: typeof r.category === 'string' ? r.category : null,
      fixRecommendation: typeof r.fixRecommendation === 'string' ? r.fixRecommendation : null,
    }
  })
  const accepted = store.addFindings(deviceId, findings)
  return { status: 202, body: { accepted, securityScore: store.securityScore(deviceId) } }
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

// ─── Breach monitors (dashboard Bearer) ─────────────────────

function hibpToExposureInput(b: HibpBreach) {
  return {
    name: b.Name,
    title: b.Title,
    domain: b.Domain,
    breachDate: b.BreachDate,
    dataClasses: b.DataClasses,
    pwnCount: b.PwnCount,
    isVerified: b.IsVerified,
    isSensitive: b.IsSensitive,
  }
}

async function refreshOneMonitor(
  store: DeviceStore,
  hibp: HibpClient,
  email: string,
): Promise<{ ok: boolean; source: string; error?: string; added: number }> {
  const monitor = store.getBreachMonitorByEmail(email)
  if (!monitor) return { ok: false, source: 'error', error: 'monitor not found', added: 0 }
  const lookup = await hibp.lookupBreaches(monitor.email)
  store.markBreachMonitorChecked(monitor.id)
  if (lookup.breaches.length > 0) {
    const { added } = store.upsertBreachExposures(
      monitor.id,
      lookup.breaches.map(hibpToExposureInput),
    )
    return { ok: lookup.ok, source: lookup.source, error: lookup.error, added }
  }
  return { ok: lookup.ok, source: lookup.source, error: lookup.error, added: 0 }
}

/** GET /v1/breach-monitors — list monitors + exposures (BreachMonitorResult shape). */
export function listBreachMonitors(store: DeviceStore): HandlerResult {
  return { status: 200, body: store.getBreachMonitorResult() }
}

/**
 * POST /v1/breach-monitors — add email, run HIBP/stub lookup, upsert exposures.
 * Body: `{ email: string }`
 */
export async function createBreachMonitor(
  store: DeviceStore,
  input: unknown,
  hibp: HibpClient,
): Promise<HandlerResult> {
  const o = (input ?? {}) as Record<string, unknown>
  const emailRaw = typeof o.email === 'string' ? o.email : ''
  const added = store.addBreachMonitor(emailRaw)
  if ('error' in added) {
    if (added.error === 'invalid_email') {
      return { status: 400, body: { error: 'invalid email' } }
    }
    return { status: 409, body: { error: 'breach monitor limit reached', limit: BREACH_MONITOR_LIMIT } }
  }
  const lookup = await hibp.lookupBreaches(added.monitor.email)
  store.markBreachMonitorChecked(added.monitor.id)
  if (lookup.breaches.length > 0) {
    store.upsertBreachExposures(added.monitor.id, lookup.breaches.map(hibpToExposureInput))
  }
  const result = store.getBreachMonitorResult()
  return {
    status: added.created ? 201 : 200,
    body: {
      ...result,
      created: added.created,
      source: lookup.source,
      ...(lookup.error ? { lookupError: lookup.error } : {}),
    },
  }
}

/** DELETE /v1/breach-monitors/{email} */
export function deleteBreachMonitor(store: DeviceStore, email: string): HandlerResult {
  const normalized = normalizeEmail(email)
  if (!normalized) return { status: 400, body: { error: 'invalid email' } }
  if (!store.removeBreachMonitor(normalized)) {
    return { status: 404, body: { error: 'breach monitor not found' } }
  }
  return { status: 200, body: store.getBreachMonitorResult() }
}

/** POST /v1/breach-monitors/acknowledge — body `{ breachIds: string[] }` */
export function acknowledgeBreachExposures(store: DeviceStore, input: unknown): HandlerResult {
  const o = (input ?? {}) as Record<string, unknown>
  const raw = Array.isArray(o.breachIds)
    ? o.breachIds
    : Array.isArray(o.breach_ids)
      ? o.breach_ids
      : null
  if (!raw || raw.length === 0) {
    return { status: 400, body: { error: 'breachIds must be a non-empty array' } }
  }
  if (raw.length > 100) {
    return { status: 400, body: { error: 'breachIds max 100' } }
  }
  const ids = raw.filter((id): id is string => typeof id === 'string' && id.length > 0)
  if (ids.length === 0) {
    return { status: 400, body: { error: 'breachIds must be a non-empty array' } }
  }
  const acknowledged = store.acknowledgeBreaches(ids)
  return {
    status: 200,
    body: {
      status: 'ok',
      acknowledged,
      ...store.getBreachMonitorResult(),
    },
  }
}

/**
 * POST /v1/breach-monitors/refresh — re-check one or all monitors.
 * Body optional: `{ email?: string }`
 */
export async function refreshBreachMonitors(
  store: DeviceStore,
  input: unknown,
  hibp: HibpClient,
): Promise<HandlerResult> {
  const o = (input ?? {}) as Record<string, unknown>
  const emailRaw = typeof o.email === 'string' ? o.email.trim() : ''
  if (emailRaw) {
    const normalized = normalizeEmail(emailRaw)
    if (!normalized) return { status: 400, body: { error: 'invalid email' } }
    if (!store.getBreachMonitorByEmail(normalized)) {
      return { status: 404, body: { error: 'breach monitor not found' } }
    }
    const r = await refreshOneMonitor(store, hibp, normalized)
    return {
      status: 200,
      body: {
        ...store.getBreachMonitorResult(),
        source: r.source,
        refreshed: 1,
        added: r.added,
        ...(r.error ? { lookupError: r.error } : {}),
      },
    }
  }

  const monitors = store.listBreachMonitors()
  let added = 0
  let source: string = 'stub'
  let lookupError: string | undefined
  for (const m of monitors) {
    if (m.monitoringPaused) continue
    const r = await refreshOneMonitor(store, hibp, m.email)
    added += r.added
    source = r.source
    if (r.error) lookupError = r.error
  }
  return {
    status: 200,
    body: {
      ...store.getBreachMonitorResult(),
      source,
      refreshed: monitors.filter((m) => !m.monitoringPaused).length,
      added,
      ...(lookupError ? { lookupError } : {}),
    },
  }
}
