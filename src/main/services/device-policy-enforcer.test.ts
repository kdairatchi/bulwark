import { describe, it, expect, afterEach, vi } from 'vitest'
import { DevicePolicyEnforcer, parseRemotePolicy } from './device-policy-enforcer'
import { DnsResolver } from './dns-resolver'
import dgram from 'dgram'
import { parseQuestion } from './dns-filter'

vi.mock('./logger', () => ({ cloudLog: vi.fn() }))

function query(name: string, qtype = 1): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x4242, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]))
  const qname = Buffer.concat([...labels, Buffer.from([0])])
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(1, 2)
  return Buffer.concat([header, qname, tail])
}

function udpQuery(port: number, msg: Buffer, timeoutMs = 2000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    const timer = setTimeout(() => { sock.close(); reject(new Error('timeout')) }, timeoutMs)
    sock.on('message', (res) => { clearTimeout(timer); sock.close(); resolve(res) })
    sock.on('error', (e) => { clearTimeout(timer); sock.close(); reject(e) })
    sock.send(msg, port, '127.0.0.1')
  })
}

describe('parseRemotePolicy', () => {
  it('fills defaults and normalizes domains', () => {
    const p = parseRemotePolicy({
      version: 3,
      isolated: true,
      blockedDomains: [' Tracker.Malware.TEST. ', 'bad'],
      isolationAllowlist: ['GoogleAPIs.com'],
    })
    expect(p.version).toBe(3)
    expect(p.isolated).toBe(true)
    expect(p.blockedDomains).toEqual(['tracker.malware.test'])
    expect(p.isolationAllowlist).toEqual(['googleapis.com'])
  })
})

describe('DevicePolicyEnforcer', () => {
  const resolver = new DnsResolver()
  afterEach(async () => {
    await resolver.stop()
  })

  it('blockDomain records an event and reports applied', async () => {
    const enforcer = new DevicePolicyEnforcer()
    enforcer.setLocalBlocklistProvider(() => [])
    // Ephemeral port — CI Win/mac cannot bind :5353 (EACCES / EADDRINUSE).
    enforcer.setResolverStartConfig({ port: 0 })
    const { dnsResolver } = await import('./dns-resolver')
    try {
      const result = await enforcer.blockDomain('evil.example.test')
      expect(result.ok).toBe(true)
      expect(result.stub).toBe(false)
      expect(result.applied).toBe(true)
      expect(result.domain).toBe('evil.example.test')
      const events = enforcer.drainEvents()
      expect(events.some((e) => e.type === 'dns_policy_block_added')).toBe(true)
    } finally {
      await dnsResolver.stop()
      dnsResolver.setOnBlocked(null)
      dnsResolver.setFilterMode('blocklist', [])
      enforcer.resetForTest()
    }
  })

  it('isolation allowlist sinkholes non-allowlisted names on a local resolver', async () => {
    resolver.setFilterMode('allowlist', ['googleapis.com'])
    const stats = await resolver.start({ port: 0 as unknown as number, upstreamHost: '203.0.113.1' })
    const port = Number(stats.address!.split(':')[1])
    const res = await udpQuery(port, query('tracker.malware.test', 1))
    expect(parseQuestion(res)?.name).toBe('tracker.malware.test')
    expect([...res.subarray(res.length - 4)]).toEqual([0, 0, 0, 0])
    expect(resolver.getStats().blockedQueries).toBe(1)
    expect(resolver.getFilterMode()).toBe('allowlist')
  })
})
