/**
 * Parent / operator dashboard client for the Bulwark device API.
 * Uses unsigned dashboard routes on the reference service: list devices,
 * mint pairing codes, push policy, emergency isolate, and read events.
 */

import { DeviceApiHttpError } from './device-api-client'

export interface DashboardDevice {
  id: string
  name: string
  os: string | null
  enrolledAt: string
  lastHeartbeat: string | null
  inventoryCount: number
  findingsCount: number
  isolated: boolean
  policyVersion: number
  dnsGuardRequired: boolean
  blockedDomains: string[]
}

export interface DashboardPolicy {
  version: number
  updatedAt: string
  isolated: boolean
  dnsGuardRequired: boolean
  blockedDomains: string[]
  isolationAllowlist: string[]
  allowInstallUnknown: boolean
}

export interface DashboardNetworkEvent {
  id: string
  deviceId: string
  type: string
  at: string
  subject: string | null
  detail: string | null
  metadata: Record<string, unknown>
}

export interface DashboardFinding {
  id: string
  deviceId: string
  level: string
  subjectName: string
  reason: string
  createdAt: string
}

export interface DashboardApiClientOptions {
  baseUrl: string
  fetchImpl?: typeof fetch
}

function joinUrl(base: string, path: string): string {
  return base.replace(/\/+$/, '') + path
}

async function parseJson(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    return { raw: text }
  }
}

export class DashboardApiClient {
  readonly baseUrl: string
  private readonly fetchImpl: typeof fetch

  constructor(opts: DashboardApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetchImpl ?? fetch
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    const hasBody = body !== undefined && method !== 'GET' && method !== 'HEAD' && method !== 'DELETE'
    const rawBody = hasBody ? JSON.stringify(body) : ''
    const res = await this.fetchImpl(joinUrl(this.baseUrl, path), {
      method,
      headers: hasBody || method === 'POST' || method === 'PUT'
        ? { 'Content-Type': 'application/json' }
        : undefined,
      body: hasBody ? rawBody : undefined,
    })
    return { status: res.status, body: await parseJson(res) }
  }

  async createPairingCode(): Promise<{ code: string; expiresAt: string }> {
    const { status, body } = await this.request('POST', '/v1/pairing-codes', {})
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as { code?: string; expiresAt?: string }
    if (!o.code) throw new DeviceApiHttpError(status, body)
    return { code: o.code, expiresAt: o.expiresAt ?? '' }
  }

  async listDevices(): Promise<DashboardDevice[]> {
    const { status, body } = await this.request('GET', '/v1/devices')
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const devices = (body as { devices?: unknown }).devices
    return Array.isArray(devices) ? (devices as DashboardDevice[]) : []
  }

  async putPolicy(deviceId: string, patch: Partial<{
    isolated: boolean
    dnsGuardRequired: boolean
    allowInstallUnknown: boolean
    blockedDomains: string[]
    isolationAllowlist: string[]
  }>): Promise<{ policy: DashboardPolicy; command: { type: string } }> {
    const { status, body } = await this.request('PUT', `/v1/devices/${deviceId}/policy`, patch)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { policy: DashboardPolicy; command: { type: string } }
  }

  async isolateDevice(deviceId: string, reason?: string): Promise<{
    policy: DashboardPolicy
    command: { type: string }
  }> {
    const { status, body } = await this.request(
      'POST',
      `/v1/devices/${deviceId}/isolate`,
      reason ? { reason } : {},
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { policy: DashboardPolicy; command: { type: string } }
  }

  async clearIsolation(deviceId: string): Promise<{
    policy: DashboardPolicy
    command: { type: string }
  }> {
    const { status, body } = await this.request('DELETE', `/v1/devices/${deviceId}/isolate`)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { policy: DashboardPolicy; command: { type: string } }
  }

  async listNetworkEvents(deviceId?: string): Promise<DashboardNetworkEvent[]> {
    const path = deviceId
      ? `/v1/network-events?deviceId=${encodeURIComponent(deviceId)}`
      : '/v1/network-events'
    const { status, body } = await this.request('GET', path)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const events = (body as { events?: unknown }).events
    return Array.isArray(events) ? (events as DashboardNetworkEvent[]) : []
  }

  async listFindings(deviceId?: string): Promise<DashboardFinding[]> {
    const path = deviceId
      ? `/v1/findings?deviceId=${encodeURIComponent(deviceId)}`
      : '/v1/findings'
    const { status, body } = await this.request('GET', path)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const findings = (body as { findings?: unknown }).findings
    return Array.isArray(findings) ? (findings as DashboardFinding[]) : []
  }

  async issueCommand(
    deviceId: string,
    type: string,
    parameters: Record<string, unknown> = {},
  ): Promise<{ command: { commandId: string; type: string } }> {
    const { status, body } = await this.request(
      'POST',
      `/v1/devices/${deviceId}/commands`,
      { type, parameters },
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { command: { commandId: string; type: string } }
  }
}

/** Resolve dashboard base URL from payload or env default. */
export function resolveDashboardBaseUrl(input?: string): string {
  const raw = (input ?? process.env.DEVICE_API_URL ?? 'http://127.0.0.1:8787').trim()
  return raw.replace(/\/+$/, '') || 'http://127.0.0.1:8787'
}
