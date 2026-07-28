/**
 * Desktop agent for the Bulwark device API: pairing enrollment, heartbeat,
 * and secure remote-command poll → verify → execute → report.
 *
 * Parallel to (not inside) the legacy Pusher/API-key cloud-agent.
 * Imports only crypto + commands from src/cloud/device-api — never the HTTP server.
 */

import { hostname, platform, release } from 'os'
import { generateDeviceKeyPair } from '../../cloud/device-api/crypto'
import {
  verifyCommandEnvelope,
  type CommandEnvelope,
  type CommandType,
} from '../../cloud/device-api/commands'
import { DeviceApiClient, DeviceApiHttpError } from './device-api-client'
import {
  loadDeviceIdentity,
  saveDeviceIdentity,
  clearDeviceIdentity,
  type DeviceIdentity,
} from './device-identity-store'
import {
  devicePolicyEnforcer,
  parseRemotePolicy,
} from './device-policy-enforcer'
import { collectDesktopInventory } from './desktop-inventory'
import { executeRemoteScan } from './desktop-remote-scans'
import { executeUpdateThreatFeeds, executeQuarantineFile, executeRestartAgent } from './desktop-remote-actions'
import { getPlatform } from '../platform'
import { cloudLog } from './logger'

const DEFAULT_BASE_URL = process.env.DEVICE_API_URL || 'http://127.0.0.1:8787'
const DEFAULT_POLL_MS = 15_000
const INVENTORY_SYNC_MS = 5 * 60 * 1000
const MAX_SEEN_NONCES = 500

/** Pairing codes are human-enterable like `K7Q2-9F3M` (hex; dash optional on input). */
export function normalizePairingCode(raw: string): string {
  const cleaned = raw.trim().toUpperCase().replace(/[^A-F0-9]/g, '')
  if (cleaned.length === 8) return `${cleaned.slice(0, 4)}-${cleaned.slice(4)}`
  return ''
}

export function isValidPairingCode(code: string): boolean {
  return /^[A-F0-9]{4}-[A-F0-9]{4}$/.test(normalizePairingCode(code))
}

export interface DeviceAgentStatus {
  enrolled: boolean
  running: boolean
  deviceId: string | null
  name: string | null
  baseUrl: string | null
  enrolledAt: string | null
  lastHeartbeatAt: string | null
  lastPollAt: string | null
  lastCommandAt: string | null
  lastCommandType: string | null
  lastError: string | null
  commandsProcessed: number
  commandsRejected: number
}

export type CommandExecutor = (
  type: CommandType,
  parameters: Record<string, unknown>,
) => Promise<Record<string, unknown>>

/** Default allowlisted handlers — inventory/scans use real local posture data. */
export async function defaultCommandExecutor(
  type: CommandType,
  parameters: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  switch (type) {
    case 'REQUEST_INVENTORY': {
      try {
        const payload = await collectDesktopInventory({
          loadApps: () => getPlatform().commands.getInstalledApps(),
          platform: `${platform()} ${release()}`,
          hostname: hostname(),
        })
        return {
          ok: true,
          stub: false,
          type,
          count: payload.count,
          findingCount: payload.findings.length,
          hostname: payload.hostname,
          platform: payload.platform,
          // Embedded for agent-bound sync (stripped from command result if desired).
          _inventory: payload,
          parameters,
        }
      } catch (err) {
        return {
          ok: false,
          stub: false,
          type,
          error: err instanceof Error ? err.message : String(err),
          parameters,
        }
      }
    }
    case 'RUN_MALWARE_SCAN':
    case 'RUN_VULNERABILITY_SCAN':
    case 'RUN_HEALTH_ASSESSMENT': {
      try {
        const apps = await getPlatform().commands.getInstalledApps()
        return await executeRemoteScan(type, apps, parameters)
      } catch (err) {
        return {
          ok: false,
          stub: false,
          type,
          threatsFound: 0,
          findings: 0,
          error: err instanceof Error ? err.message : String(err),
          parameters,
        }
      }
    }
    case 'UPDATE_THREAT_FEEDS':
      return executeUpdateThreatFeeds(parameters)
    case 'QUARANTINE_FILE':
      return executeQuarantineFile(parameters)
    case 'BLOCK_DOMAIN': {
      const domain = typeof parameters.domain === 'string'
        ? parameters.domain
        : typeof parameters.host === 'string' ? parameters.host : ''
      return devicePolicyEnforcer.blockDomain(domain)
    }
    case 'ISOLATE_DEVICE':
    case 'CLEAR_ISOLATION':
    case 'APPLY_POLICY':
      // Prefer the agent-bound executor (pulls fresh policy). Fallback keeps stubs honest.
      return {
        ok: true,
        stub: true,
        type,
        applied: false,
        reason: 'policy commands require agent-bound executor',
        parameters,
      }
    case 'RESTART_AGENT':
      return executeRestartAgent(parameters)
    default:
      return { ok: false, error: 'unhandled command type', type }
  }
}

/**
 * Pure command processing used by the agent and unit tests.
 * Verifies the envelope, records the nonce, executes, returns the result payload.
 */
export async function processVerifiedCommand(opts: {
  serverPublicKeyPem: string
  deviceId: string
  cmd: CommandEnvelope
  seenNonces: Set<string>
  now: number
  execute: CommandExecutor
}): Promise<{ accepted: true; result: Record<string, unknown> } | { accepted: false; reason: string }> {
  const verify = verifyCommandEnvelope(opts.serverPublicKeyPem, opts.cmd, {
    now: opts.now,
    deviceId: opts.deviceId,
    seenNonces: opts.seenNonces,
  })
  if (!verify.ok) return { accepted: false, reason: verify.reason }
  opts.seenNonces.add(opts.cmd.nonce)
  while (opts.seenNonces.size > MAX_SEEN_NONCES) {
    const first = opts.seenNonces.values().next().value
    if (first === undefined) break
    opts.seenNonces.delete(first)
  }
  try {
    const result = await opts.execute(opts.cmd.type, opts.cmd.parameters ?? {})
    return { accepted: true, result: { ...result, commandId: opts.cmd.commandId, type: opts.cmd.type } }
  } catch (err) {
    return {
      accepted: true,
      result: {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        commandId: opts.cmd.commandId,
        type: opts.cmd.type,
      },
    }
  }
}

export class DeviceCommandAgent {
  private identity: DeviceIdentity | null = null
  private timer: ReturnType<typeof setInterval> | null = null
  private running = false
  private tickInFlight = false
  private seenNonces = new Set<string>()
  private lastHeartbeatAt: string | null = null
  private lastPollAt: string | null = null
  private lastCommandAt: string | null = null
  private lastCommandType: string | null = null
  private lastError: string | null = null
  private lastInventoryAt = 0
  private commandsProcessed = 0
  private commandsRejected = 0
  private readonly pollMs: number
  private readonly execute: CommandExecutor
  private readonly fetchImpl?: typeof fetch
  private readonly inventorySyncMs: number

  constructor(opts?: {
    pollMs?: number
    execute?: CommandExecutor
    fetchImpl?: typeof fetch
    inventorySyncMs?: number
  }) {
    this.pollMs = opts?.pollMs ?? DEFAULT_POLL_MS
    this.execute = opts?.execute ?? defaultCommandExecutor
    this.fetchImpl = opts?.fetchImpl
    this.inventorySyncMs = opts?.inventorySyncMs ?? INVENTORY_SYNC_MS
  }

  /**
   * Test/demo helper: inject an enrolled identity without pairing I/O.
   * Sets lastInventoryAt so the next tick skips an immediate inventory sync.
   */
  setIdentityForTest(identity: DeviceIdentity | null): void {
    this.identity = identity
    this.lastInventoryAt = identity ? Date.now() : 0
    if (!identity) {
      this.seenNonces.clear()
      this.commandsProcessed = 0
      this.commandsRejected = 0
    }
  }

  /** Wait until any in-flight tick completes (tests). */
  async waitForIdle(timeoutMs = 10_000): Promise<void> {
    const start = Date.now()
    while (this.tickInFlight) {
      if (Date.now() - start > timeoutMs) throw new Error('device-api agent tick idle timeout')
      await new Promise((r) => setTimeout(r, 15))
    }
  }

  getStatus(): DeviceAgentStatus {
    return {
      enrolled: !!this.identity,
      running: this.running,
      deviceId: this.identity?.deviceId ?? null,
      name: this.identity?.name ?? null,
      baseUrl: this.identity?.baseUrl ?? null,
      enrolledAt: this.identity?.enrolledAt ?? null,
      lastHeartbeatAt: this.lastHeartbeatAt,
      lastPollAt: this.lastPollAt,
      lastCommandAt: this.lastCommandAt,
      lastCommandType: this.lastCommandType,
      lastError: this.lastError,
      commandsProcessed: this.commandsProcessed,
      commandsRejected: this.commandsRejected,
    }
  }

  /** Load persisted identity (if any) and start polling. */
  start(): void {
    if (this.running) return
    this.identity = loadDeviceIdentity()
    if (!this.identity) {
      cloudLog('INFO', 'device-api agent idle (not enrolled)')
      return
    }
    this.running = true
    cloudLog('INFO', 'device-api agent started', { deviceId: this.identity.deviceId, baseUrl: this.identity.baseUrl })
    void this.tick()
    this.timer = setInterval(() => { void this.tick() }, this.pollMs)
  }

  stop(): void {
    this.running = false
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
  }

  async enroll(input: {
    code: string
    name?: string
    baseUrl?: string
  }): Promise<{ success: true; deviceId: string } | { success: false; error: string }> {
    const code = normalizePairingCode(input.code)
    if (!isValidPairingCode(code)) {
      return { success: false, error: 'Invalid pairing code' }
    }
    const baseUrl = (input.baseUrl?.trim() || DEFAULT_BASE_URL).replace(/\/+$/, '')
    const name = (input.name?.trim() || hostname() || 'Bulwark Device').slice(0, 80)
    const client = new DeviceApiClient({ baseUrl, fetchImpl: this.fetchImpl })
    try {
      const keys = generateDeviceKeyPair()
      const enrolled = await client.enroll({
        code,
        name,
        publicKeyPem: keys.publicKeyPem,
        os: `${platform()} ${release()}`,
      })
      const serverKey = await client.getServerKey()
      const identity: DeviceIdentity = {
        deviceId: enrolled.deviceId,
        name,
        publicKeyPem: keys.publicKeyPem,
        privateKeyPem: keys.privateKeyPem,
        serverPublicKeyPem: serverKey.publicKeyPem,
        baseUrl,
        enrolledAt: enrolled.enrolledAt || new Date().toISOString(),
      }
      saveDeviceIdentity(identity)
      this.identity = identity
      this.lastError = null
      this.stop()
      this.start()
      cloudLog('INFO', 'device-api enrolled', { deviceId: identity.deviceId })
      return { success: true, deviceId: identity.deviceId }
    } catch (err) {
      const msg = err instanceof DeviceApiHttpError
        ? `HTTP ${err.status}: ${JSON.stringify(err.body)}`
        : err instanceof Error ? err.message : String(err)
      this.lastError = msg
      cloudLog('ERROR', 'device-api enroll failed', { error: msg })
      return { success: false, error: msg }
    }
  }

  async unenroll(): Promise<void> {
    this.stop()
    clearDeviceIdentity()
    this.identity = null
    this.seenNonces.clear()
    this.lastError = null
    this.commandsProcessed = 0
    this.commandsRejected = 0
    cloudLog('INFO', 'device-api unenrolled')
  }

  /** One poll cycle — exposed for tests and demos. */
  async tick(): Promise<void> {
    if (!this.identity || this.tickInFlight) return
    this.tickInFlight = true
    try {
      const client = new DeviceApiClient({ baseUrl: this.identity.baseUrl, fetchImpl: this.fetchImpl })
      await client.heartbeat(this.identity.privateKeyPem, this.identity.deviceId)
      this.lastHeartbeatAt = new Date().toISOString()

      // Pull latest policy each tick (parity with Android TV agent).
      try {
        const policy = parseRemotePolicy(
          await client.getPolicy(this.identity.privateKeyPem, this.identity.deviceId),
        )
        await devicePolicyEnforcer.applyRemotePolicy(policy)
      } catch (err) {
        cloudLog('INFO', 'device-api policy pull failed', {
          error: err instanceof Error ? err.message : String(err),
        })
      }

      const commands = await client.pollCommands(this.identity.privateKeyPem, this.identity.deviceId)
      this.lastPollAt = new Date().toISOString()
      for (const cmd of commands) {
        await this.handleCommand(client, cmd)
      }

      // Periodic inventory sync (also runs immediately when never synced).
      if (Date.now() - this.lastInventoryAt >= this.inventorySyncMs) {
        try {
          await this.syncInventory(client)
        } catch (err) {
          cloudLog('INFO', 'device-api inventory sync failed', {
            error: err instanceof Error ? err.message : String(err),
          })
        }
      }

      const events = devicePolicyEnforcer.drainEvents()
      if (events.length > 0) {
        try {
          await client.submitNetworkEvents(
            this.identity.privateKeyPem,
            this.identity.deviceId,
            events,
          )
        } catch (err) {
          cloudLog('INFO', 'device-api event flush failed', {
            error: err instanceof Error ? err.message : String(err),
            count: events.length,
          })
        }
      }
      this.lastError = null
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      this.lastError = msg
      cloudLog('ERROR', 'device-api tick failed', { error: msg })
    } finally {
      this.tickInFlight = false
    }
  }

  /** Collect installed apps, POST inventory + findings to the control plane. */
  private async syncInventory(client: DeviceApiClient): Promise<{ count: number; findingCount: number }> {
    if (!this.identity) return { count: 0, findingCount: 0 }
    const payload = await collectDesktopInventory({
      loadApps: () => getPlatform().commands.getInstalledApps(),
      platform: `${platform()} ${release()}`,
      hostname: hostname(),
    })
    await client.submitInventory(this.identity.privateKeyPem, this.identity.deviceId, {
      apps: payload.apps,
      count: payload.count,
      platform: payload.platform,
      hostname: payload.hostname,
    })
    if (payload.findings.length > 0) {
      await client.submitFindings(this.identity.privateKeyPem, this.identity.deviceId, payload.findings)
      for (const f of payload.findings.slice(0, 20)) {
        devicePolicyEnforcer.pushEvent('finding', f.subjectName, f.reason)
      }
    }
    this.lastInventoryAt = Date.now()
    cloudLog('INFO', 'device-api inventory synced', {
      count: payload.count,
      findings: payload.findings.length,
    })
    return { count: payload.count, findingCount: payload.findings.length }
  }

  private async handleCommand(client: DeviceApiClient, cmd: CommandEnvelope): Promise<void> {
    if (!this.identity) return
    const identity = this.identity
    const execute: CommandExecutor = async (type, parameters) => {
      if (type === 'APPLY_POLICY' || type === 'ISOLATE_DEVICE' || type === 'CLEAR_ISOLATION') {
        const policy = parseRemotePolicy(
          await client.getPolicy(identity.privateKeyPem, identity.deviceId),
        )
        return devicePolicyEnforcer.applyRemotePolicy(policy)
      }
      if (type === 'REQUEST_INVENTORY') {
        const synced = await this.syncInventory(client)
        return {
          ok: true,
          stub: false,
          type,
          count: synced.count,
          findingCount: synced.findingCount,
          hostname: hostname(),
          platform: `${platform()} ${release()}`,
        }
      }
      if (
        type === 'RUN_HEALTH_ASSESSMENT'
        || type === 'RUN_MALWARE_SCAN'
        || type === 'RUN_VULNERABILITY_SCAN'
      ) {
        const result = await this.execute(type, parameters)
        const embedded = Array.isArray(result._findings)
          ? result._findings as Array<{
            level: string
            subjectName: string
            reason: string
            category?: string
            fixRecommendation?: string
          }>
          : []
        if (embedded.length > 0) {
          await client.submitFindings(identity.privateKeyPem, identity.deviceId, embedded)
          for (const f of embedded.slice(0, 20)) {
            devicePolicyEnforcer.pushEvent('finding', f.subjectName, f.reason)
          }
        }
        return result
      }
      if (type === 'BLOCK_DOMAIN') {
        return defaultCommandExecutor(type, parameters)
      }
      return this.execute(type, parameters)
    }
    const processed = await processVerifiedCommand({
      serverPublicKeyPem: this.identity.serverPublicKeyPem,
      deviceId: this.identity.deviceId,
      cmd,
      seenNonces: this.seenNonces,
      now: Date.now(),
      execute,
    })
    if (!processed.accepted) {
      this.commandsRejected++
      cloudLog('INFO', 'device-api command rejected', { commandId: cmd.commandId, reason: processed.reason })
      // Still report rejection so the cloud can clear the queue entry.
      try {
        await client.postCommandResult(this.identity.privateKeyPem, this.identity.deviceId, cmd.commandId, {
          ok: false,
          rejected: true,
          reason: processed.reason,
        })
      } catch { /* ignore report failure */ }
      return
    }
    try {
      // Never post bulky embedded payloads back as command results.
      const { _inventory: _dropInv, _findings: _dropFind, ...safeResult } = processed.result
      await client.postCommandResult(
        this.identity.privateKeyPem,
        this.identity.deviceId,
        cmd.commandId,
        safeResult,
      )
      this.commandsProcessed++
      this.lastCommandAt = new Date().toISOString()
      this.lastCommandType = cmd.type
      cloudLog('INFO', 'device-api command completed', { commandId: cmd.commandId, type: cmd.type })
    } catch (err) {
      cloudLog('ERROR', 'device-api result post failed', {
        commandId: cmd.commandId,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }
}

export const deviceCommandAgent = new DeviceCommandAgent()
