// In-memory store for the device API (a real deployment would use PostgreSQL —
// see docs/architecture). Kept dependency-free and deterministic-friendly:
// id/time generators are injectable for tests.

import { randomUUID, randomBytes } from 'crypto'
import { generateDeviceKeyPair } from './crypto'
import { signCommand, isAllowedCommand, type CommandEnvelope, type CommandType } from './commands'

const COMMAND_TTL_MS = 5 * 60 * 1000

export interface PairingCode {
  code: string
  createdAt: string
  expiresAt: number
  used: boolean
}

export interface DeviceAgentStatus {
  dnsGuardRunning: boolean
  vpnConsentPending: boolean
  isolatedReported: boolean
  filterMode: string | null
  updatedAt: string
}

export interface Device {
  id: string
  name: string
  publicKeyPem: string
  os: string | null
  enrolledAt: string
  lastHeartbeat: string | null
  inventoryCount: number
  findingsCount: number
  /** Last agent-reported DNS Guard / consent snapshot from inventory. */
  agentStatus: DeviceAgentStatus | null
}

/** Review / lifecycle statuses for dashboard findings (see docs/api). */
export const FINDING_STATUSES = [
  'confirmed_affected',
  'likely_affected',
  'potential_match',
  'not_exploitable',
  'fixed',
  'accepted_risk',
  'false_positive',
  'unknown',
] as const

export type StoredFindingStatus = (typeof FINDING_STATUSES)[number]

export function isFindingStatus(value: string): value is StoredFindingStatus {
  return (FINDING_STATUSES as readonly string[]).includes(value)
}

/** Statuses that no longer count against the device security score. */
export const RESOLVED_FINDING_STATUSES = new Set<StoredFindingStatus>([
  'false_positive',
  'accepted_risk',
  'fixed',
  'not_exploitable',
])

export interface StoredFinding {
  id: string
  deviceId: string
  level: string
  subjectName: string
  reason: string
  /** Optional taxonomy from agents (kev, osv, technique, lolbin, …). */
  category: string | null
  createdAt: string
  updatedAt: string | null
  status: StoredFindingStatus
  reviewedAt: string | null
  reviewNote: string | null
}

/** Sanitize finding category from agent payloads. */
export function normalizeFindingCategory(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const c = raw.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '').slice(0, 40)
  return c || null
}

/**
 * Level penalty (points deducted from 100), then scaled by category weight.
 * KEV/OSV/ransomware hurt more than unknown-publisher noise.
 */
export function findingPenalty(finding: Pick<StoredFinding, 'level' | 'category' | 'reason'>): number {
  const level = finding.level.toLowerCase()
  let base = 8
  if (level.includes('critical') || level.includes('likely') || level === 'dangerous') base = 25
  else if (level.includes('high') || level.includes('confirmed')) base = 20
  else if (level.includes('medium') || level.includes('potential')) base = 10
  else if (level === 'safe' || level === 'low') base = 2

  const cat = (finding.category || '').toLowerCase()
  const reason = (finding.reason || '').toLowerCase()
  let weight = 1
  if (cat === 'kev' || cat === 'osv' || cat === 'cve') {
    weight = reason.includes('ransomware') ? 1.6 : 1.35
  } else if (cat === 'technique' || cat === 'vuln_heuristic' || cat === 'lolbin') {
    weight = 1.15
  } else if (cat === 'sideload' || cat === 'malware') {
    weight = 1.2
  } else if (cat === 'health' || cat === 'risk') {
    weight = 0.85
  }
  return Math.round(base * weight)
}

export interface AuditEvent {
  at: string
  event: string
  detail?: string
}

export interface StoreDeps {
  now: () => number
  uuid: () => string
  code: () => string
  /** Bearer token required for dashboard write routes. */
  dashboardToken?: string
  /**
   * When true, `GET /v1/dashboard-bootstrap` returns the token (local/dev only).
   * Defaults to true when the token was auto-generated (not from env/deps).
   */
  allowDashboardBootstrap?: boolean
}

const defaultDeps: StoreDeps = {
  now: () => Date.now(),
  uuid: () => randomUUID(),
  // Human-enterable pairing code, e.g. "A933-8F5C" (8 hex digits).
  code: () => {
    const raw = randomBytes(4).toString('hex').toUpperCase()
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}`
  },
}

const PAIRING_TTL_MS = 5 * 60 * 1000

export interface CommandRecord {
  envelope: CommandEnvelope
  status: 'pending' | 'completed'
  result?: unknown
  completedAt?: string
}

/** Remote policy pushed to agents (TV/desktop). */
export interface DevicePolicy {
  version: number
  updatedAt: string
  isolated: boolean
  dnsGuardRequired: boolean
  blockedDomains: string[]
  /** When isolated, only these domains (and their parents) may resolve. */
  isolationAllowlist: string[]
  allowInstallUnknown: boolean
}

function defaultPolicy(now: number): DevicePolicy {
  return {
    version: 1,
    updatedAt: new Date(now).toISOString(),
    isolated: false,
    dnsGuardRequired: false,
    blockedDomains: [],
    isolationAllowlist: [
      'googleapis.com',
      'gvt1.com',
      'android.com',
      'google.com',
      'cloudflare.com',
      '1.1.1.1',
    ],
    allowInstallUnknown: false,
  }
}

function resolveDashboardAuth(deps: Partial<StoreDeps>): { token: string; allowBootstrap: boolean } {
  const envToken = typeof process !== 'undefined' && process.env.DASHBOARD_TOKEN
    ? process.env.DASHBOARD_TOKEN.trim()
    : ''
  if (deps.dashboardToken && deps.dashboardToken.trim()) {
    return {
      token: deps.dashboardToken.trim(),
      allowBootstrap: deps.allowDashboardBootstrap === true,
    }
  }
  if (envToken) {
    return {
      token: envToken,
      allowBootstrap: deps.allowDashboardBootstrap === true,
    }
  }
  return {
    token: randomBytes(24).toString('hex'),
    allowBootstrap: deps.allowDashboardBootstrap !== false,
  }
}

export class DeviceStore {
  private pairing = new Map<string, PairingCode>()
  private devices = new Map<string, Device>()
  private findings: StoredFinding[] = []
  private audit: AuditEvent[] = []
  private commands = new Map<string, CommandRecord>()
  private policies = new Map<string, DevicePolicy>()
  private deps: StoreDeps
  private serverKeys = generateDeviceKeyPair()
  private readonly dashboardTokenValue: string
  private readonly allowDashboardBootstrap: boolean

  constructor(deps: Partial<StoreDeps> = {}) {
    this.deps = { ...defaultDeps, ...deps }
    const auth = resolveDashboardAuth(deps)
    this.dashboardTokenValue = auth.token
    this.allowDashboardBootstrap = auth.allowBootstrap
  }

  /** Bearer token for dashboard write routes. */
  dashboardToken(): string {
    return this.dashboardTokenValue
  }

  /** Whether GET /v1/dashboard-bootstrap may return the token (local/dev). */
  canBootstrapDashboard(): boolean {
    return this.allowDashboardBootstrap
  }

  /** Constant-time-ish compare for Bearer tokens. */
  verifyDashboardToken(candidate: string | undefined | null): boolean {
    if (!candidate || !this.dashboardTokenValue) return false
    if (candidate.length !== this.dashboardTokenValue.length) return false
    let diff = 0
    for (let i = 0; i < candidate.length; i++) {
      diff |= candidate.charCodeAt(i) ^ this.dashboardTokenValue.charCodeAt(i)
    }
    return diff === 0
  }

  /** Public key devices use to verify command signatures. */
  serverPublicKey(): string {
    return this.serverKeys.publicKeyPem
  }

  /** Dashboard side: create + sign an allowlisted command for a device. */
  issueCommand(deviceId: string, type: string, parameters: Record<string, unknown> = {}): CommandEnvelope | null {
    if (!this.devices.has(deviceId) || !isAllowedCommand(type)) return null
    const now = this.deps.now()
    const envelope = signCommand(this.serverKeys.privateKeyPem, {
      commandId: `cmd_${this.deps.uuid()}`,
      deviceId,
      type: type as CommandType,
      parameters,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + COMMAND_TTL_MS).toISOString(),
      nonce: this.deps.uuid(),
    })
    this.commands.set(envelope.commandId, { envelope, status: 'pending' })
    this.log('command_issued', `${deviceId} ${type} ${envelope.commandId}`)
    return envelope
  }

  pendingCommands(deviceId: string): CommandEnvelope[] {
    return [...this.commands.values()]
      .filter((c) => c.status === 'pending' && c.envelope.deviceId === deviceId)
      .map((c) => c.envelope)
  }

  /** Record a device's command result. Returns false if unknown/mismatched. */
  recordCommandResult(deviceId: string, commandId: string, result: unknown): boolean {
    const rec = this.commands.get(commandId)
    if (!rec || rec.envelope.deviceId !== deviceId) return false
    rec.status = 'completed'
    rec.result = result
    rec.completedAt = new Date(this.deps.now()).toISOString()
    this.log('command_result', `${deviceId} ${commandId}`)
    return true
  }

  getCommand(commandId: string): CommandRecord | undefined {
    return this.commands.get(commandId)
  }

  private log(event: string, detail?: string): void {
    this.audit.push({ at: new Date(this.deps.now()).toISOString(), event, detail })
  }

  auditLog(): AuditEvent[] {
    return [...this.audit]
  }

  createPairingCode(): PairingCode {
    const now = this.deps.now()
    const pc: PairingCode = {
      code: this.deps.code(),
      createdAt: new Date(now).toISOString(),
      expiresAt: now + PAIRING_TTL_MS,
      used: false,
    }
    this.pairing.set(pc.code, pc)
    this.log('pairing_code_created', pc.code)
    return pc
  }

  /** Consume a pairing code; returns false if missing/used/expired. */
  consumePairingCode(code: string): boolean {
    const pc = this.pairing.get(code)
    if (!pc || pc.used || this.deps.now() > pc.expiresAt) return false
    pc.used = true
    return true
  }

  enrollDevice(input: { name: string; publicKeyPem: string; os?: string | null }): Device {
    const device: Device = {
      id: `dev_${this.deps.uuid()}`,
      name: input.name,
      publicKeyPem: input.publicKeyPem,
      os: input.os ?? null,
      enrolledAt: new Date(this.deps.now()).toISOString(),
      lastHeartbeat: null,
      inventoryCount: 0,
      findingsCount: 0,
      agentStatus: null,
    }
    this.devices.set(device.id, device)
    this.log('device_enrolled', device.id)
    return device
  }

  getDevice(id: string): Device | undefined {
    return this.devices.get(id)
  }

  listDevices(): Device[] {
    return [...this.devices.values()]
  }

  recordHeartbeat(deviceId: string): void {
    const d = this.devices.get(deviceId)
    if (d) d.lastHeartbeat = new Date(this.deps.now()).toISOString()
  }

  addInventory(deviceId: string, count: number, agentStatus?: Partial<DeviceAgentStatus> | null): void {
    const d = this.devices.get(deviceId)
    if (d) {
      d.inventoryCount += count
      if (agentStatus) {
        d.agentStatus = {
          dnsGuardRunning: agentStatus.dnsGuardRunning === true,
          vpnConsentPending: agentStatus.vpnConsentPending === true,
          isolatedReported: agentStatus.isolatedReported === true,
          filterMode: typeof agentStatus.filterMode === 'string' ? agentStatus.filterMode : null,
          updatedAt: new Date(this.deps.now()).toISOString(),
        }
      }
    }
    this.log('inventory_received', `${deviceId} +${count}`)
  }

  addFindings(deviceId: string, findings: Array<Omit<StoredFinding, 'id' | 'deviceId' | 'createdAt' | 'updatedAt' | 'status' | 'reviewedAt' | 'reviewNote'> & {
    status?: string
    category?: string | null
  }>): number {
    const d = this.devices.get(deviceId)
    if (!d) return 0
    let accepted = 0
    const nowIso = new Date(this.deps.now()).toISOString()
    for (const f of findings) {
      const status = typeof f.status === 'string' && isFindingStatus(f.status)
        ? f.status
        : (isFindingStatus(f.level) ? f.level : 'potential_match')
      const category = normalizeFindingCategory(f.category)
      const subjectName = f.subjectName
      const reason = f.reason
      const level = f.level

      // Dedupe open findings by (subjectName, category) — refresh in place.
      const openMatch = this.findings.find(
        (x) =>
          x.deviceId === deviceId
          && !RESOLVED_FINDING_STATUSES.has(x.status)
          && x.subjectName === subjectName
          && (x.category || null) === category,
      )
      if (openMatch) {
        openMatch.level = level
        openMatch.reason = reason
        openMatch.updatedAt = nowIso
        // Keep existing status if it's a review-style open status; otherwise align with level.
        if (!isFindingStatus(openMatch.status) || openMatch.status === 'unknown') {
          openMatch.status = status
        }
        accepted++
        continue
      }

      this.findings.push({
        id: `finding_${this.deps.uuid()}`,
        deviceId,
        level,
        subjectName,
        reason,
        category,
        createdAt: nowIso,
        updatedAt: null,
        status,
        reviewedAt: null,
        reviewNote: null,
      })
      accepted++
    }
    d.findingsCount = this.findings.filter((f) => f.deviceId === deviceId).length
    // Soft cap memory for the reference control plane.
    const deviceFindings = this.findings.filter((f) => f.deviceId === deviceId)
    if (deviceFindings.length > 500) {
      const drop = deviceFindings.length - 500
      const ids = new Set(deviceFindings.slice(0, drop).map((f) => f.id))
      this.findings = this.findings.filter((f) => !ids.has(f.id))
      d.findingsCount = this.findings.filter((f) => f.deviceId === deviceId).length
    }
    this.log('findings_received', `${deviceId} +${accepted}`)
    return accepted
  }

  listFindings(deviceId?: string): StoredFinding[] {
    return deviceId ? this.findings.filter((f) => f.deviceId === deviceId) : [...this.findings]
  }

  getFinding(id: string): StoredFinding | undefined {
    return this.findings.find((f) => f.id === id)
  }

  reviewFinding(
    id: string,
    status: StoredFindingStatus,
    note?: string | null,
  ): StoredFinding | null {
    const f = this.getFinding(id)
    if (!f) return null
    f.status = status
    f.reviewedAt = new Date(this.deps.now()).toISOString()
    f.reviewNote = typeof note === 'string' && note.trim() ? note.trim().slice(0, 500) : null
    this.log('finding_reviewed', `${id} → ${status}`)
    return f
  }

  openFindings(deviceId: string): StoredFinding[] {
    return this.findings.filter(
      (f) => f.deviceId === deviceId && !RESOLVED_FINDING_STATUSES.has(f.status),
    )
  }

  /**
   * 0–100 security score from open findings (100 = nothing needs attention).
   * Resolved reviews (false_positive / accepted_risk / fixed / not_exploitable) do not penalize.
   * Category-aware: KEV/OSV/ransomware weigh more than publisher noise.
   */
  securityScore(deviceId: string): number {
    const open = this.openFindings(deviceId)
    if (open.length === 0) return 100
    let penalty = 0
    for (const f of open) {
      penalty += findingPenalty(f)
    }
    return Math.max(0, Math.min(100, 100 - penalty))
  }

  private networkEvents: Array<{ id: string; deviceId: string; type: string; at: string; subject: string | null; detail: string | null; metadata: Record<string, unknown> }> = []

  addNetworkEvents(deviceId: string, events: Array<{ type: string; at?: string; subject?: string | null; detail?: string | null; metadata?: Record<string, unknown> }>): number {
    if (!this.devices.has(deviceId)) return 0
    let n = 0
    for (const e of events) {
      if (typeof e.type !== 'string' || !e.type) continue
      this.networkEvents.push({
        id: `evt_${this.deps.uuid()}`,
        deviceId,
        type: e.type,
        at: typeof e.at === 'string' ? e.at : new Date(this.deps.now()).toISOString(),
        subject: typeof e.subject === 'string' ? e.subject : null,
        detail: typeof e.detail === 'string' ? e.detail : null,
        metadata: (e.metadata && typeof e.metadata === 'object') ? e.metadata : {},
      })
      n++
    }
    // Cap memory for the reference service.
    if (this.networkEvents.length > 5000) {
      this.networkEvents.splice(0, this.networkEvents.length - 5000)
    }
    this.log('network_events_received', `${deviceId} +${n}`)
    return n
  }

  listNetworkEvents(deviceId?: string): typeof this.networkEvents {
    return deviceId ? this.networkEvents.filter((e) => e.deviceId === deviceId) : [...this.networkEvents]
  }

  getPolicy(deviceId: string): DevicePolicy | null {
    if (!this.devices.has(deviceId)) return null
    return this.policies.get(deviceId) ?? defaultPolicy(this.deps.now())
  }

  /** Merge patch into device policy; bumps version. */
  updatePolicy(deviceId: string, patch: Partial<DevicePolicy>): DevicePolicy | null {
    if (!this.devices.has(deviceId)) return null
    const current = this.getPolicy(deviceId)!
    const next: DevicePolicy = {
      ...current,
      ...patch,
      blockedDomains: patch.blockedDomains ?? current.blockedDomains,
      isolationAllowlist: patch.isolationAllowlist ?? current.isolationAllowlist,
      version: current.version + 1,
      updatedAt: new Date(this.deps.now()).toISOString(),
    }
    this.policies.set(deviceId, next)
    this.log('policy_updated', `${deviceId} v${next.version}`)
    return next
  }

  /**
   * Dashboard emergency isolate: flip policy.isolated and enqueue a signed
   * ISOLATE_DEVICE command so the agent acts immediately.
   */
  isolateDevice(deviceId: string, reason?: string): { policy: DevicePolicy; command: CommandEnvelope } | null {
    if (!this.devices.has(deviceId)) return null
    const policy = this.updatePolicy(deviceId, {
      isolated: true,
      dnsGuardRequired: true,
    })!
    const command = this.issueCommand(deviceId, 'ISOLATE_DEVICE', { reason: reason ?? 'dashboard' })
    if (!command) return null
    this.log('device_isolated', `${deviceId} ${reason ?? ''}`.trim())
    return { policy, command }
  }

  clearIsolation(deviceId: string): { policy: DevicePolicy; command: CommandEnvelope } | null {
    if (!this.devices.has(deviceId)) return null
    const policy = this.updatePolicy(deviceId, { isolated: false })!
    const command = this.issueCommand(deviceId, 'CLEAR_ISOLATION', {})
    if (!command) return null
    this.log('device_isolation_cleared', deviceId)
    return { policy, command }
  }
}
