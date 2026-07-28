import { describe, it, expect } from 'vitest'
import { DeviceStore, BREACH_MONITOR_LIMIT } from './store'
import {
  listBreachMonitors,
  createBreachMonitor,
  deleteBreachMonitor,
  acknowledgeBreachExposures,
  refreshBreachMonitors,
} from './handlers'
import { createHibpClient, type HibpClient, type HibpLookupResult } from './hibp-client'
import { createDeviceApiServer } from './server'
import type { Server } from 'http'

function freshStore() {
  let n = 0
  return new DeviceStore({
    uuid: () => `id${++n}`,
    code: () => 'TEST-CODE',
    now: () => 1_700_000_000_000,
  })
}

function stubHibp(): HibpClient {
  return createHibpClient({ stub: true })
}

describe('breach monitor handlers', () => {
  it('creates a monitor, looks up stub breaches, and lists them', async () => {
    const store = freshStore()
    const hibp = stubHibp()
    const created = await createBreachMonitor(store, { email: 'pwned@example.com' }, hibp)
    expect(created.status).toBe(201)
    const body = created.body as {
      usage: number
      limit: number
      source: string
      emails: Array<{ email: string; fresh: boolean; breaches: Array<{ name: string; id: string }> }>
    }
    expect(body.source).toBe('stub')
    expect(body.usage).toBe(1)
    expect(body.limit).toBe(BREACH_MONITOR_LIMIT)
    expect(body.emails[0].email).toBe('pwned@example.com')
    expect(body.emails[0].fresh).toBe(true)
    expect(body.emails[0].breaches.length).toBeGreaterThanOrEqual(1)
    expect(body.emails[0].breaches[0].id).toMatch(/^be_/)

    const listed = listBreachMonitors(store)
    expect(listed.status).toBe(200)
    expect((listed.body as { usage: number }).usage).toBe(1)
  })

  it('returns empty breaches for clean emails in stub mode', async () => {
    const store = freshStore()
    const res = await createBreachMonitor(store, { email: 'safe@example.com' }, stubHibp())
    expect(res.status).toBe(201)
    const body = res.body as { emails: Array<{ breaches: unknown[] }>; source: string }
    expect(body.source).toBe('stub')
    expect(body.emails[0].breaches).toEqual([])
  })

  it('rejects invalid email and enforces limit', async () => {
    const store = freshStore()
    const hibp = stubHibp()
    expect((await createBreachMonitor(store, { email: 'nope' }, hibp)).status).toBe(400)

    for (let i = 0; i < BREACH_MONITOR_LIMIT; i++) {
      const r = await createBreachMonitor(store, { email: `user${i}@example.com` }, hibp)
      expect(r.status).toBe(201)
    }
    const over = await createBreachMonitor(store, { email: 'extra@example.com' }, hibp)
    expect(over.status).toBe(409)
  })

  it('idempotent re-add returns 200 without duplicating', async () => {
    const store = freshStore()
    const hibp = stubHibp()
    expect((await createBreachMonitor(store, { email: 'A@B.com' }, hibp)).status).toBe(201)
    const again = await createBreachMonitor(store, { email: 'a@b.com' }, hibp)
    expect(again.status).toBe(200)
    expect((again.body as { usage: number; created: boolean }).usage).toBe(1)
    expect((again.body as { created: boolean }).created).toBe(false)
  })

  it('acknowledges breaches and preserves ack on refresh upsert', async () => {
    const store = freshStore()
    const hibp = stubHibp()
    await createBreachMonitor(store, { email: 'breach@hibp-test.bulwark.local' }, hibp)
    const listed = listBreachMonitors(store).body as {
      emails: Array<{ breaches: Array<{ id: string; name: string; acknowledgedAt: string | null }> }>
    }
    const ids = listed.emails[0].breaches.map((b) => b.id)
    expect(ids.length).toBeGreaterThanOrEqual(1)

    const ack = acknowledgeBreachExposures(store, { breachIds: [ids[0]] })
    expect(ack.status).toBe(200)
    expect((ack.body as { acknowledged: number }).acknowledged).toBe(1)

    const afterAck = listBreachMonitors(store).body as {
      emails: Array<{ breaches: Array<{ id: string; acknowledgedAt: string | null }> }>
    }
    const acked = afterAck.emails[0].breaches.find((b) => b.id === ids[0])
    expect(acked?.acknowledgedAt).toBeTruthy()

    await refreshBreachMonitors(store, { email: 'breach@hibp-test.bulwark.local' }, hibp)
    const afterRefresh = listBreachMonitors(store).body as {
      emails: Array<{ breaches: Array<{ id: string; acknowledgedAt: string | null }> }>
    }
    const still = afterRefresh.emails[0].breaches.find((b) => b.id === ids[0])
    expect(still?.acknowledgedAt).toBe(acked?.acknowledgedAt)
  })

  it('deletes a monitor and its exposures', async () => {
    const store = freshStore()
    await createBreachMonitor(store, { email: 'pwned@example.com' }, stubHibp())
    const del = deleteBreachMonitor(store, 'pwned@example.com')
    expect(del.status).toBe(200)
    expect((del.body as { usage: number }).usage).toBe(0)
    expect(deleteBreachMonitor(store, 'pwned@example.com').status).toBe(404)
  })

  it('refresh unknown email returns 404', async () => {
    const store = freshStore()
    const r = await refreshBreachMonitors(store, { email: 'missing@example.com' }, stubHibp())
    expect(r.status).toBe(404)
  })
})

describe('breach monitor HTTP routes', () => {
  let server: Server | null = null
  let base = ''

  async function start(store: DeviceStore, hibp?: HibpClient) {
    server = createDeviceApiServer(store, hibp ? { hibp } : { hibp: stubHibp() })
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()))
    const addr = server!.address()
    if (!addr || typeof addr === 'string') throw new Error('no address')
    base = `http://127.0.0.1:${addr.port}`
  }

  async function stop() {
    if (!server) return
    await new Promise<void>((resolve, reject) => server!.close((e) => (e ? reject(e) : resolve())))
    server = null
  }

  it('requires bearer and supports create/list/ack/delete via HTTP', async () => {
    const store = freshStore()
    await start(store)
    try {
      const unauth = await fetch(`${base}/v1/breach-monitors`)
      expect(unauth.status).toBe(401)

      const headers = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${store.dashboardToken()}`,
      }

      const created = await fetch(`${base}/v1/breach-monitors`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email: 'leaked@hibp-test.bulwark.local' }),
      })
      expect(created.status).toBe(201)
      const createdBody = (await created.json()) as {
        source: string
        emails: Array<{ breaches: Array<{ id: string }> }>
      }
      expect(createdBody.source).toBe('stub')
      const breachId = createdBody.emails[0].breaches[0].id

      const listed = await fetch(`${base}/v1/breach-monitors`, { headers })
      expect(listed.status).toBe(200)

      const ack = await fetch(`${base}/v1/breach-monitors/acknowledge`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ breachIds: [breachId] }),
      })
      expect(ack.status).toBe(200)
      expect((await ack.json() as { acknowledged: number }).acknowledged).toBe(1)

      const refresh = await fetch(`${base}/v1/breach-monitors/refresh`, {
        method: 'POST',
        headers,
        body: JSON.stringify({}),
      })
      expect(refresh.status).toBe(200)

      const del = await fetch(
        `${base}/v1/breach-monitors/${encodeURIComponent('leaked@hibp-test.bulwark.local')}`,
        { method: 'DELETE', headers },
      )
      expect(del.status).toBe(200)
      expect((await del.json() as { usage: number }).usage).toBe(0)
    } finally {
      await stop()
    }
  })

  it('injects a custom hibp client', async () => {
    const store = freshStore()
    const custom: HibpClient = {
      async lookupBreaches(): Promise<HibpLookupResult> {
        return {
          ok: true,
          source: 'hibp',
          breaches: [{
            Name: 'Custom',
            Title: 'Custom Breach',
            Domain: 'custom.test',
            BreachDate: '2024-01-01',
            DataClasses: ['Emails'],
            PwnCount: 1,
            IsVerified: true,
            IsSensitive: false,
          }],
        }
      },
    }
    await start(store, custom)
    try {
      const headers = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${store.dashboardToken()}`,
      }
      const res = await fetch(`${base}/v1/breach-monitors`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ email: 'anyone@example.com' }),
      })
      const body = (await res.json()) as {
        source: string
        emails: Array<{ breaches: Array<{ name: string }> }>
      }
      expect(body.source).toBe('hibp')
      expect(body.emails[0].breaches[0].name).toBe('Custom')
    } finally {
      await stop()
    }
  })
})
