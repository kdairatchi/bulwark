/**
 * Parent / operator dashboard client for the Bulwark device API.
 * Dashboard read + write routes require Authorization: Bearer <dashboard-token>
 * (except GET /v1/dashboard-bootstrap and GET /v1/server-key).
 * Local/dev servers expose GET /v1/dashboard-bootstrap when the token was auto-generated.
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
  openFindingsCount: number
  securityScore: number
  isolated: boolean
  policyVersion: number
  dnsGuardRequired: boolean
  blockedDomains: string[]
  dnsGuardRunning?: boolean
  vpnConsentPending?: boolean
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
  category?: string | null
  fixRecommendation?: string | null
  createdAt: string
  updatedAt?: string | null
  status: string
  reviewedAt: string | null
  reviewNote: string | null
}

export interface DashboardBreachEntry {
  id: string
  name: string
  title: string
  domain: string
  breachDate: string
  dataClasses: string[]
  pwnCount: number
  isVerified: boolean
  isSensitive: boolean
  acknowledgedAt: string | null
}

export interface DashboardMonitoredEmail {
  email: string
  lastCheckedAt: string | null
  fresh: boolean
  monitoringPaused: boolean
  breaches: DashboardBreachEntry[]
}

export interface DashboardBreachMonitorResult {
  emails: DashboardMonitoredEmail[]
  limit: number
  usage: number
  source?: string
  created?: boolean
}

export interface DashboardFleetSummary {
  deviceCount: number
  onlineCount: number
  avgSecurityScore: number
  worstSecurityScore: number
  openFindingsTotal: number
  openKevTotal: number
  isolatedCount: number
  dnsBlockedRecent: number
  unackedBreaches: number
}

export interface DashboardFleetDeviceRow {
  id: string
  name: string
  os: string | null
  lastHeartbeat: string | null
  securityScore: number
  openFindingsCount: number
  openKevCount: number
  isolated: boolean
  inventoryCount: number
  dnsBlockedCount: number
}

export interface DashboardFleetReport {
  generatedAt: string
  summary: DashboardFleetSummary
  devices: DashboardFleetDeviceRow[]
  count: number
}

export interface DashboardAlert {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | string
  type: 'kev_finding' | 'isolation' | 'dns_blocked' | 'breach' | string
  subject: string
  detail?: string | null
  at: string
  deviceId: string | null
  acknowledged: boolean
}

export interface DashboardApiClientOptions {
  baseUrl: string
  /** Bearer token for dashboard read/write routes. */
  token?: string
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
  private token: string
  private readonly fetchImpl: typeof fetch

  constructor(opts: DashboardApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.token = (opts.token ?? '').trim()
    this.fetchImpl = opts.fetchImpl ?? fetch
  }

  setToken(token: string): void {
    this.token = token.trim()
  }

  getToken(): string {
    return this.token
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
    opts?: { auth?: boolean },
  ): Promise<{ status: number; body: unknown }> {
    const hasBody = body !== undefined && method !== 'GET' && method !== 'HEAD' && method !== 'DELETE'
    const rawBody = hasBody ? JSON.stringify(body) : ''
    const headers: Record<string, string> = {}
    if (hasBody || method === 'POST' || method === 'PUT') {
      headers['Content-Type'] = 'application/json'
    }
    if (opts?.auth !== false && this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }
    const res = await this.fetchImpl(joinUrl(this.baseUrl, path), {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: hasBody ? rawBody : undefined,
    })
    return { status: res.status, body: await parseJson(res) }
  }

  /** Fetch token from local/dev bootstrap endpoint (no auth). */
  async bootstrap(): Promise<{ token: string }> {
    const { status, body } = await this.request('GET', '/v1/dashboard-bootstrap', undefined, { auth: false })
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as { token?: string }
    if (!o.token) throw new DeviceApiHttpError(status, body)
    this.token = o.token
    return { token: o.token }
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

  /** Sugar for enqueueing RUN_*_SCAN / RUN_HEALTH_ASSESSMENT. */
  async requestScan(
    deviceId: string,
    kind: 'health' | 'malware' | 'vulnerability' | 'lolbins',
    opts?: { scope?: string; kevSync?: boolean; osv?: boolean; epss?: boolean },
  ): Promise<{ command: { commandId: string; type: string } }> {
    const payload: Record<string, unknown> = { kind }
    if (opts?.scope) payload.scope = opts.scope
    if (opts?.kevSync !== undefined) payload.kevSync = opts.kevSync
    if (opts?.osv !== undefined) payload.osv = opts.osv
    if (opts?.epss !== undefined) payload.epss = opts.epss
    const { status, body } = await this.request('POST', `/v1/devices/${deviceId}/scan`, payload)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    return body as { command: { commandId: string; type: string } }
  }

  async reviewFinding(
    findingId: string,
    status: string,
    note?: string,
  ): Promise<{
    finding: DashboardFinding
    securityScore: number
    openFindingsCount: number
  }> {
    const payload: Record<string, unknown> = { status }
    if (note) payload.note = note
    const { status: httpStatus, body } = await this.request(
      'POST',
      `/v1/findings/${encodeURIComponent(findingId)}/review`,
      payload,
    )
    if (httpStatus < 200 || httpStatus >= 300) throw new DeviceApiHttpError(httpStatus, body)
    return body as {
      finding: DashboardFinding
      securityScore: number
      openFindingsCount: number
    }
  }

  async listBreachMonitors(): Promise<DashboardBreachMonitorResult> {
    const { status, body } = await this.request('GET', '/v1/breach-monitors')
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as DashboardBreachMonitorResult
    return {
      emails: Array.isArray(o.emails) ? o.emails : [],
      limit: typeof o.limit === 'number' ? o.limit : 10,
      usage: typeof o.usage === 'number' ? o.usage : 0,
    }
  }

  async createBreachMonitor(email: string): Promise<DashboardBreachMonitorResult> {
    const { status, body } = await this.request('POST', '/v1/breach-monitors', { email })
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as DashboardBreachMonitorResult
    return {
      emails: Array.isArray(o.emails) ? o.emails : [],
      limit: typeof o.limit === 'number' ? o.limit : 10,
      usage: typeof o.usage === 'number' ? o.usage : 0,
      source: o.source,
      created: o.created,
    }
  }

  async deleteBreachMonitor(email: string): Promise<void> {
    const { status, body } = await this.request(
      'DELETE',
      `/v1/breach-monitors/${encodeURIComponent(email)}`,
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
  }

  async acknowledgeBreaches(breachIds: string[]): Promise<{ acknowledged: number }> {
    const { status, body } = await this.request(
      'POST',
      '/v1/breach-monitors/acknowledge',
      { breachIds },
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as { acknowledged?: number }
    return { acknowledged: typeof o.acknowledged === 'number' ? o.acknowledged : 0 }
  }

  async refreshBreachMonitors(email?: string): Promise<DashboardBreachMonitorResult> {
    const { status, body } = await this.request(
      'POST',
      '/v1/breach-monitors/refresh',
      email ? { email } : {},
    )
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as DashboardBreachMonitorResult
    return {
      emails: Array.isArray(o.emails) ? o.emails : [],
      limit: typeof o.limit === 'number' ? o.limit : 10,
      usage: typeof o.usage === 'number' ? o.usage : 0,
      source: o.source,
    }
  }

  async getFleetReport(): Promise<DashboardFleetReport> {
    const { status, body } = await this.request('GET', '/v1/reports')
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const o = body as DashboardFleetReport
    return {
      generatedAt: typeof o.generatedAt === 'string' ? o.generatedAt : new Date().toISOString(),
      summary: o.summary ?? {
        deviceCount: 0,
        onlineCount: 0,
        avgSecurityScore: 0,
        worstSecurityScore: 100,
        openFindingsTotal: 0,
        openKevTotal: 0,
        isolatedCount: 0,
        dnsBlockedRecent: 0,
        unackedBreaches: 0,
      },
      devices: Array.isArray(o.devices) ? o.devices : [],
      count: typeof o.count === 'number' ? o.count : (Array.isArray(o.devices) ? o.devices.length : 0),
    }
  }

  async listAlerts(opts?: { deviceId?: string; limit?: number }): Promise<DashboardAlert[]> {
    const params = new URLSearchParams()
    if (opts?.deviceId) params.set('deviceId', opts.deviceId)
    if (typeof opts?.limit === 'number') params.set('limit', String(opts.limit))
    const q = params.toString()
    const path = q ? `/v1/alerts?${q}` : '/v1/alerts'
    const { status, body } = await this.request('GET', path)
    if (status < 200 || status >= 300) throw new DeviceApiHttpError(status, body)
    const alerts = (body as { alerts?: unknown }).alerts
    return Array.isArray(alerts) ? (alerts as DashboardAlert[]) : []
  }
}

/** Resolve dashboard base URL from payload or env default. */
export function resolveDashboardBaseUrl(input?: string): string {
  const raw = (input ?? process.env.DEVICE_API_URL ?? 'http://127.0.0.1:8787').trim()
  return raw.replace(/\/+$/, '') || 'http://127.0.0.1:8787'
}

/** Resolve dashboard token from payload or env. */
export function resolveDashboardToken(input?: string): string {
  return (input ?? process.env.DASHBOARD_TOKEN ?? '').trim()
}
