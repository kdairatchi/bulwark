import { describe, it, expect, afterEach } from 'vitest'
import dgram from 'dgram'
import { DnsResolver } from './dns-resolver'
import { parseQuestion } from './dns-filter'

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

describe('dns-resolver · blocked-path integration', () => {
  const resolver = new DnsResolver()
  afterEach(async () => { await resolver.stop() })

  it('sinkholes a blocked domain over UDP without contacting upstream', async () => {
    resolver.setBlocklist(['doubleclick.net'])
    // Point upstream at an unroutable address so any forward attempt would fail;
    // the blocked path must answer locally regardless.
    const stats = await resolver.start({ port: 0 as unknown as number, upstreamHost: '203.0.113.1' })
    // port 0 → OS-assigned; read the actual bound port from stats address.
    const port = Number(stats.address!.split(':')[1])

    const res = await udpQuery(port, query('stats.g.doubleclick.net', 1))
    const q = parseQuestion(res)
    expect(q?.name).toBe('stats.g.doubleclick.net')
    expect(res.readUInt16BE(6)).toBe(1) // one answer
    expect([...res.subarray(res.length - 4)]).toEqual([0, 0, 0, 0]) // 0.0.0.0 sinkhole

    const after = resolver.getStats()
    expect(after.blockedQueries).toBe(1)
    expect(after.forwardedQueries).toBe(0)
  })

  it('reports running status and address', async () => {
    await resolver.start({ port: 0 as unknown as number })
    const stats = resolver.getStats()
    expect(stats.running).toBe(true)
    expect(stats.address).toMatch(/^127\.0\.0\.1:\d+$/)
  })
})
