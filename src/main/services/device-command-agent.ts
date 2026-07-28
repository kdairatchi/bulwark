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
import { cloudLog } from './logger'

const DEFAULT_BASE_URL = process.env.DEVICE_API_URL || 'http://127.0.0.1:8787'
const DEFAULT_POLL_MS = 15_000
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

/** Default allowlisted stubs — real scanners wire in later. */
export async function defaultCommandExecutor(
  type: CommandType,
  parameters: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  switch (type) {
    case 'REQUEST_INVENTORY':
      return {
        ok: true,
        stub: true,
        type,
        hostname: hostname(),
        platform: platform(),
        release: release(),
        parameters,
      }
    case 'RUN_MALWARE_SCAN':
    case 'RUN_VULNERABILITY_SCAN':
    case 'RUN_HEALTH_ASSESSMENT':
      return { ok: true, stub: true, type, threatsFound: 0, findings: 0, parameters }
    case 'UPDATE_THREAT_FEEDS':
      return { ok: true, stub: true, type, updated: false, parameters }
    case 'QUARANTINE_FILE':
    case 'BLOCK_DOMAIN':
      return { ok: true, stub: true, type, applied: false, reason: 'stub — awaiting enforcement wiring', parameters }
    case 'ISOLATE_DEVICE':
      return { ok: true, stub: true, type, applied: true, isolated: true, parameters }
    case 'CLEAR_ISOLATION':
      return { ok: true, stub: true, type, applied: true, isolated: false, parameters }
    case 'APPLY_POLICY':
      return { ok: true, stub: true, type, applied: true, parameters }
    case 'RESTART_AGENT':
      return { ok: true, stub: true, type, scheduled: false, parameters }
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
  private commandsProcessed = 0
  private commandsRejected = 0
  private readonly pollMs: number
  private readonly execute: CommandExecutor
  private readonly fetchImpl?: typeof fetch

  constructor(opts?: {
    pollMs?: number
    execute?: CommandExecutor
    fetchImpl?: typeof fetch
  }) {
    this.pollMs = opts?.pollMs ?? DEFAULT_POLL_MS
    this.execute = opts?.execute ?? defaultCommandExecutor
    this.fetchImpl = opts?.fetchImpl
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
      const commands = await client.pollCommands(this.identity.privateKeyPem, this.identity.deviceId)
      this.lastPollAt = new Date().toISOString()
      for (const cmd of commands) {
        await this.handleCommand(client, cmd)
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

  private async handleCommand(client: DeviceApiClient, cmd: CommandEnvelope): Promise<void> {
    if (!this.identity) return
    const processed = await processVerifiedCommand({
      serverPublicKeyPem: this.identity.serverPublicKeyPem,
      deviceId: this.identity.deviceId,
      cmd,
      seenNonces: this.seenNonces,
      now: Date.now(),
      execute: this.execute,
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
      await client.postCommandResult(
        this.identity.privateKeyPem,
        this.identity.deviceId,
        cmd.commandId,
        processed.result,
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
