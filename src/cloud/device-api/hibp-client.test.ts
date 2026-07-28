import { describe, it, expect, vi } from 'vitest'
import {
  createHibpClient,
  normalizeEmail,
  emailLookupHash,
  type HibpBreach,
} from './hibp-client'

describe('normalizeEmail', () => {
  it('lowercases and trims', () => {
    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com')
  })

  it('rejects empty / invalid / too-long', () => {
    expect(normalizeEmail('')).toBeNull()
    expect(normalizeEmail('not-an-email')).toBeNull()
    expect(normalizeEmail('a@b')).toBeNull()
    expect(normalizeEmail(`${'a'.repeat(250)}@x.com`)).toBeNull()
  })
})

describe('emailLookupHash', () => {
  it('is stable for equivalent emails', () => {
    expect(emailLookupHash('A@B.COM')).toBe(emailLookupHash('a@b.com'))
    expect(emailLookupHash('a@b.com')).toMatch(/^[a-f0-9]{64}$/)
  })
})

describe('createHibpClient stub mode', () => {
  it('defaults to stub without apiKey', async () => {
    const client = createHibpClient()
    const clean = await client.lookupBreaches('safe@example.com')
    expect(clean).toMatchObject({ ok: true, source: 'stub', breaches: [] })

    const pwned = await client.lookupBreaches('pwned@example.com')
    expect(pwned.ok).toBe(true)
    expect(pwned.source).toBe('stub')
    expect(pwned.breaches.length).toBeGreaterThanOrEqual(1)
    expect(pwned.breaches[0].Name).toBeTruthy()
  })

  it('triggers fixtures for hibp-test domain and breach keywords', async () => {
    const client = createHibpClient({ stub: true })
    const a = await client.lookupBreaches('user@hibp-test.bulwrk.local')
    expect(a.breaches.map((b) => b.Name)).toEqual(expect.arrayContaining(['Adobe', 'LinkedIn']))

    const linked = await client.lookupBreaches('linkedin-breach@example.com')
    expect(linked.breaches).toHaveLength(1)
    expect(linked.breaches[0].Name).toBe('LinkedIn')

    const adobe = await client.lookupBreaches('adobe-leaked@example.com')
    expect(adobe.breaches).toHaveLength(1)
    expect(adobe.breaches[0].Name).toBe('Adobe')
  })

  it('forces stub even with apiKey when stub: true', async () => {
    const fetchImpl = vi.fn()
    const client = createHibpClient({ apiKey: 'secret', stub: true, fetchImpl })
    const r = await client.lookupBreaches('pwned@example.com')
    expect(r.source).toBe('stub')
    expect(fetchImpl).not.toHaveBeenCalled()
  })
})

describe('createHibpClient live mode', () => {
  it('calls HIBP with headers and maps breaches', async () => {
    const fixture: HibpBreach = {
      Name: 'TestBreach',
      Title: 'Test Breach',
      Domain: 'test.example',
      BreachDate: '2020-01-01',
      DataClasses: ['Email addresses'],
      PwnCount: 42,
      IsVerified: true,
      IsSensitive: false,
    }
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify([fixture]), { status: 200 }),
    ) as unknown as typeof fetch

    const client = createHibpClient({
      apiKey: 'test-key',
      fetchImpl,
      userAgent: 'Bulwrk-Test',
    })
    const r = await client.lookupBreaches('Alice@Example.com')
    expect(r).toEqual({ ok: true, source: 'hibp', breaches: [fixture] })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit]
    expect(url).toContain(encodeURIComponent('alice@example.com'))
    expect(url).toContain('truncateResponse=false')
    const headers = init.headers as Record<string, string>
    expect(headers['hibp-api-key']).toBe('test-key')
    expect(headers['user-agent']).toBe('Bulwrk-Test')
  })

  it('maps 404 to empty breaches', async () => {
    const fetchImpl = vi.fn(async () => new Response('', { status: 404 })) as unknown as typeof fetch
    const client = createHibpClient({ apiKey: 'k', fetchImpl })
    const r = await client.lookupBreaches('clean@example.com')
    expect(r).toEqual({ ok: true, source: 'hibp', breaches: [] })
  })

  it('soft-fails network errors', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('network down')
    }) as unknown as typeof fetch
    const client = createHibpClient({ apiKey: 'k', fetchImpl })
    const r = await client.lookupBreaches('x@y.com')
    expect(r.ok).toBe(false)
    expect(r.source).toBe('error')
    expect(r.breaches).toEqual([])
    expect(r.error).toMatch(/network down/)
  })
})
