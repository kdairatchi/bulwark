/**
 * Thin HTTP client for the Bulwark device API.
 * Reuses shared crypto helpers; does not import the Node http server.
 */

import {
  canonicalRequest,
  sha256Hex,
  signMessage,
} from '../../cloud/device-api/crypto'
import type { CommandEnvelope } from '../../cloud/device-api/commands'

export class DeviceApiHttpError extends Error {
  readonly status: number
  readonly body: unknown
  constructor(status: number, body: unknown) {
    super(`Device API HTTP ${status}`)
    this.name = 'DeviceApiHttpError'
    this.status = status
    this.body = body
  }
}

export interface DeviceApiClientOptions {
  baseUrl: string
  fetchImpl?: typeof fetch
}

export interface EnrollResult {
  deviceId: string
  enrolledAt: string
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

/** Build device-auth headers for a signed request. */
export function buildSignedHeaders(
  privateKeyPem: string,
  deviceId: string,
  method: string,
  path: string,
  rawBody: string,
  now: Date = new Date(),
): Record<string, string> {
  const timestamp = now.toISOString()
  const message = canonicalRequest(method, path, timestamp, sha256Hex(rawBody))
  return {
    'Content-Type': 'application/json',
    'X-Device-Id': deviceId,
    'X-Timestamp': timestamp,
    'X-Signature': signMessage(privateKeyPem, message),
  }
}

export class DeviceApiClient {
  readonly baseUrl: string
  private readonly fetchImpl: typeof fetch

  constructor(opts: DeviceApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetchImpl ?? fetch
  }

  private async request(method: string, path: string, init?: {
    body?: unknown
    headers?: Record<string, string>
  }): Promise<{ status: number; body: unknown }> {
    const rawBody = init?.body === undefined ? '' : JSON.stringify(init.body)
    const res = await this.fetchImpl(joinUrl(this.baseUrl, path), {
      method,
      headers: init?.headers ?? (rawBody ? { 'Content-Type': 'application/json' } : undefined),
      body: method === 'GET' || method === 'HEAD' ? undefined : rawBody || undefined,
    })
    const body = await parseJson(res)
    return { status: res.status, body }
  }

  async createPairingCode(): Promise<{ code: string; expiresAt: string }> {
    const { status, body } = await this.request('POST', '/v1/pairing-codes')
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { code: string; expiresAt: string }
  }

  async enroll(input: {
    code: string
    name: string
    publicKeyPem: string
    os?: string
  }): Promise<EnrollResult> {
    const { status, body } = await this.request('POST', '/v1/devices/enroll', { body: input })
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as EnrollResult
    if (!o.deviceId) throw new DeviceApiHttpError(status, body)
    return o
  }

  async getServerKey(): Promise<{ publicKeyPem: string }> {
    const { status, body } = await this.request('GET', '/v1/server-key')
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as { publicKeyPem: string }
    if (!o.publicKeyPem) throw new DeviceApiHttpError(status, body)
    return o
  }

  private async signed(
    privateKeyPem: string,
    deviceId: string,
    method: string,
    path: string,
    bodyObj?: unknown,
  ): Promise<{ status: number; body: unknown }> {
    const rawBody = bodyObj === undefined ? '' : JSON.stringify(bodyObj)
    const headers = buildSignedHeaders(privateKeyPem, deviceId, method, path, rawBody)
    const res = await this.fetchImpl(joinUrl(this.baseUrl, path), {
      method,
      headers,
      body: method === 'GET' ? undefined : rawBody,
    })
    return { status: res.status, body: await parseJson(res) }
  }

  async heartbeat(privateKeyPem: string, deviceId: string): Promise<void> {
    const { status, body } = await this.signed(privateKeyPem, deviceId, 'POST', `/v1/devices/${deviceId}/heartbeat`, {})
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
  }

  async pollCommands(privateKeyPem: string, deviceId: string): Promise<CommandEnvelope[]> {
    const { status, body } = await this.signed(privateKeyPem, deviceId, 'GET', `/v1/devices/${deviceId}/commands`)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const commands = (body as { commands?: unknown }).commands
    return Array.isArray(commands) ? (commands as CommandEnvelope[]) : []
  }

  async postCommandResult(
    privateKeyPem: string,
    deviceId: string,
    commandId: string,
    result: Record<string, unknown>,
  ): Promise<void> {
    const path = `/v1/devices/${deviceId}/commands/${commandId}/result`
    const { status, body } = await this.signed(privateKeyPem, deviceId, 'POST', path, result)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
  }

  async submitInventory(
    privateKeyPem: string,
    deviceId: string,
    inventory: Record<string, unknown>,
  ): Promise<void> {
    const { status, body } = await this.signed(
      privateKeyPem, deviceId, 'POST', `/v1/devices/${deviceId}/inventory`, inventory,
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
  }

  async submitFindings(
    privateKeyPem: string,
    deviceId: string,
    findings: Array<{
      level: string
      subjectName: string
      reason: string
      category?: string
      fixRecommendation?: string
    }>,
  ): Promise<number> {
    const { status, body } = await this.signed(
      privateKeyPem, deviceId, 'POST', `/v1/devices/${deviceId}/findings`, { findings },
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return typeof (body as { accepted?: number }).accepted === 'number'
      ? (body as { accepted: number }).accepted
      : findings.length
  }

  async getPolicy(privateKeyPem: string, deviceId: string): Promise<{
    version: number
    updatedAt: string
    isolated: boolean
    dnsGuardRequired: boolean
    blockedDomains: string[]
    isolationAllowlist: string[]
    allowInstallUnknown: boolean
  }> {
    const { status, body } = await this.signed(
      privateKeyPem, deviceId, 'GET', `/v1/devices/${deviceId}/policy`,
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const policy = (body as { policy?: unknown }).policy
    if (!policy || typeof policy !== 'object') throw new DeviceApiHttpError(status, body)
    return policy as {
      version: number
      updatedAt: string
      isolated: boolean
      dnsGuardRequired: boolean
      blockedDomains: string[]
      isolationAllowlist: string[]
      allowInstallUnknown: boolean
    }
  }

  async submitNetworkEvents(
    privateKeyPem: string,
    deviceId: string,
    events: Array<{
      type: string
      at?: string
      subject?: string | null
      detail?: string | null
      metadata?: Record<string, unknown>
    }>,
  ): Promise<number> {
    const { status, body } = await this.signed(
      privateKeyPem, deviceId, 'POST', `/v1/devices/${deviceId}/network-events`, { events },
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return typeof (body as { accepted?: number }).accepted === 'number'
      ? (body as { accepted: number }).accepted
      : events.length
  }
}
