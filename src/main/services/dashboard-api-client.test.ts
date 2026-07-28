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
      return { status: 201, body: { code: 'A1B2-C3D4', expiresAt: 't' } }
    })
    const client = new DashboardApiClient({ baseUrl: 'http://127.0.0.1:8787', fetchImpl: fetchImpl as unknown as typeof fetch })
    const res = await client.createPairingCode()
    expect(res.code).toBe('A1B2-C3D4')
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
})
