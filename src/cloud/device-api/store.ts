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

export interface Device {
  id: string
  name: string
  publicKeyPem: string
  os: string | null
  enrolledAt: string
  lastHeartbeat: string | null
  inventoryCount: number
  findingsCount: number
}

export interface StoredFinding {
  id: string
  deviceId: string
  level: string
  subjectName: string
  reason: string
  createdAt: string
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

export class DeviceStore {
  private pairing = new Map<string, PairingCode>()
  private devices = new Map<string, Device>()
  private findings: StoredFinding[] = []
  private audit: AuditEvent[] = []
  private commands = new Map<string, CommandRecord>()
  private policies = new Map<string, DevicePolicy>()
  private deps: StoreDeps
  private serverKeys = generateDeviceKeyPair()

  constructor(deps: Partial<StoreDeps> = {}) {
    this.deps = { ...defaultDeps, ...deps }
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

  addInventory(deviceId: string, count: number): void {
    const d = this.devices.get(deviceId)
    if (d) d.inventoryCount += count
    this.log('inventory_received', `${deviceId} +${count}`)
  }

  addFindings(deviceId: string, findings: Omit<StoredFinding, 'id' | 'deviceId' | 'createdAt'>[]): number {
    const d = this.devices.get(deviceId)
    if (!d) return 0
    for (const f of findings) {
      this.findings.push({
        id: `finding_${this.deps.uuid()}`,
        deviceId,
        level: f.level,
        subjectName: f.subjectName,
        reason: f.reason,
        createdAt: new Date(this.deps.now()).toISOString(),
      })
    }
    d.findingsCount += findings.length
    this.log('findings_received', `${deviceId} +${findings.length}`)
    return findings.length
  }

  listFindings(deviceId?: string): StoredFinding[] {
    return deviceId ? this.findings.filter((f) => f.deviceId === deviceId) : [...this.findings]
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
