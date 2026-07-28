import { describe, it, expect, vi } from 'vitest'
import { DashboardApiClient } from './dashboard-api-client'

function mockFetch(handler: (url: string, init?: RequestInit) => { status: number; body: unknown }) {
  return vi.fn(async (url: string | URL, init?: RequestInit) => {
    const { status, body } = handler(String(url), init)
    return {
      status,
      text: async () => JSON.stringify(body),
    } as Response
  })
}

describe('DashboardApiClient', () => {
  it('lists devices from GET /v1/devices', async () => {
    const fetchImpl = mockFetch((url) => {
      expect(url).toBe('http://127.0.0.1:8787/v1/devices')
      return {
        status: 200,
        body: {
          devices: [{
            id: 'dev_1', name: 'TV', os: 'Android TV', enrolledAt: 't',
            lastHeartbeat: null, inventoryCount: 0, findingsCount: 0,
            isolated: false, policyVersion: 1, dnsGuardRequired: false, blockedDomains: [],
          }],
          count: 1,
        },
      }
    })
    const client = new DashboardApiClient({ baseUrl: 'http://127.0.0.1:8787/', fetchImpl: fetchImpl as unknown as typeof fetch })
    const devices = await client.listDevices()
    expect(devices).toHaveLength(1)
    expect(devices[0].name).toBe('TV')
  })

  it('mints pairing codes', async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(url).toContain('/v1/pairing-codes')
      expect(init?.method).toBe('POST')
      expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer tok')
      return { status: 201, body: { code: 'A1B2-C3D4', expiresAt: 't' } }
    })
    const client = new DashboardApiClient({
      baseUrl: 'http://127.0.0.1:8787',
      token: 'tok',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })
    const res = await client.createPairingCode()
    expect(res.code).toBe('A1B2-C3D4')
  })

  it('bootstraps a dashboard token', async () => {
    const fetchImpl = mockFetch((url) => {
      expect(url).toContain('/v1/dashboard-bootstrap')
      return { status: 200, body: { token: 'boot-tok' } }
    })
    const client = new DashboardApiClient({
      baseUrl: 'http://127.0.0.1:8787',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })
    const res = await client.bootstrap()
    expect(res.token).toBe('boot-tok')
    expect(client.getToken()).toBe('boot-tok')
  })

  it('isolates and clears isolation', async () => {
    const calls: string[] = []
    const fetchImpl = mockFetch((url, init) => {
      calls.push(`${init?.method} ${url}`)
      return {
        status: 202,
        body: {
          policy: { isolated: init?.method === 'POST', version: 2, updatedAt: 't', dnsGuardRequired: false, blockedDomains: [], isolationAllowlist: [], allowInstallUnknown: false },
          command: { type: init?.method === 'POST' ? 'ISOLATE_DEVICE' : 'CLEAR_ISOLATION' },
        },
      }
    })
    const client = new DashboardApiClient({ baseUrl: 'http://127.0.0.1:8787', fetchImpl: fetchImpl as unknown as typeof fetch })
    const iso = await client.isolateDevice('dev_1', 'demo')
    expect(iso.command.type).toBe('ISOLATE_DEVICE')
    const cleared = await client.clearIsolation('dev_1')
    expect(cleared.command.type).toBe('CLEAR_ISOLATION')
    expect(calls[0]).toContain('POST')
    expect(calls[1]).toContain('DELETE')
  })

  it('puts policy and lists events', async () => {
    const fetchImpl = mockFetch((url, init) => {
      if (String(url).includes('/policy')) {
        expect(init?.method).toBe('PUT')
        return {
          status: 200,
          body: {
            policy: { isolated: false, version: 3, updatedAt: 't', dnsGuardRequired: true, blockedDomains: ['bad.test'], isolationAllowlist: [], allowInstallUnknown: false },
            command: { type: 'APPLY_POLICY' },
          },
        }
      }
      return {
        status: 200,
        body: { events: [{ id: 'e1', deviceId: 'dev_1', type: 'dns_blocked', at: 't', subject: 'bad.test', detail: null, metadata: {} }], count: 1 },
      }
    })
    const client = new DashboardApiClient({ baseUrl: 'http://127.0.0.1:8787', fetchImpl: fetchImpl as unknown as typeof fetch })
    const put = await client.putPolicy('dev_1', { blockedDomains: ['bad.test'], dnsGuardRequired: true })
    expect(put.command.type).toBe('APPLY_POLICY')
    const events = await client.listNetworkEvents('dev_1')
    expect(events[0].type).toBe('dns_blocked')
  })

  it('lists findings and issues commands', async () => {
    const fetchImpl = mockFetch((url, init) => {
      if (String(url).includes('/commands')) {
        expect(init?.method).toBe('POST')
        return { status: 201, body: { command: { commandId: 'cmd_1', type: 'REQUEST_INVENTORY' } } }
      }
      return {
        status: 200,
        body: {
          findings: [{ id: 'f1', deviceId: 'dev_1', level: 'potential_match', subjectName: 'Mystery', reason: 'unknown_publisher', createdAt: 't' }],
          count: 1,
        },
      }
    })
    const client = new DashboardApiClient({ baseUrl: 'http://127.0.0.1:8787', fetchImpl: fetchImpl as unknown as typeof fetch })
    const findings = await client.listFindings('dev_1')
    expect(findings[0].reason).toBe('unknown_publisher')
    const issued = await client.issueCommand('dev_1', 'REQUEST_INVENTORY')
    expect(issued.command.type).toBe('REQUEST_INVENTORY')
  })

  it('requestScan posts kind to /scan', async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(String(url)).toContain('/v1/devices/dev_1/scan')
      expect(init?.method).toBe('POST')
      expect(JSON.parse(String(init?.body))).toEqual({ kind: 'malware', scope: 'quick' })
      return { status: 201, body: { command: { commandId: 'cmd_m', type: 'RUN_MALWARE_SCAN' } } }
    })
    const client = new DashboardApiClient({
      baseUrl: 'http://127.0.0.1:8787',
      token: 'tok',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })
    const issued = await client.requestScan('dev_1', 'malware', { scope: 'quick' })
    expect(issued.command.type).toBe('RUN_MALWARE_SCAN')
  })

  it('reviewFinding posts status to /findings/{id}/review', async () => {
    const fetchImpl = mockFetch((url, init) => {
      expect(String(url)).toContain('/v1/findings/finding_1/review')
      expect(init?.method).toBe('POST')
      expect(JSON.parse(String(init?.body))).toEqual({ status: 'accepted_risk', note: 'known tool' })
      return {
        status: 200,
        body: {
          finding: { id: 'finding_1', status: 'accepted_risk', reviewedAt: 't', reviewNote: 'known tool' },
          securityScore: 90,
          openFindingsCount: 1,
        },
      }
    })
    const client = new DashboardApiClient({
      baseUrl: 'http://127.0.0.1:8787',
      token: 'tok',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    })
    const res = await client.reviewFinding('finding_1', 'accepted_risk', 'known tool')
    expect(res.securityScore).toBe(90)
    expect(res.finding.status).toBe('accepted_risk')
  })
})
