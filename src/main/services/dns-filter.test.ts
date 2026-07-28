import { describe, it, expect } from 'vitest'
import {
  parseQuestion,
  buildBlockedResponse,
  frameTcp,
  deframeTcp,
  parseHostsList,
  isBlocked,
  shouldBlockName,
  domainAndParents,
  typeName,
  parseAnswerIps,
} from './dns-filter'

/** Build a minimal DNS query for name/qtype. */
function query(name: string, qtype = 1, id = 0x1234): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // RD
  header.writeUInt16BE(1, 4) // QDCOUNT
  const labels = name.split('.').map((l) => {
    const b = Buffer.from(l, 'ascii')
    return Buffer.concat([Buffer.from([b.length]), b])
  })
  const qname = Buffer.concat([...labels, Buffer.from([0])])
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(1, 2) // IN
  return Buffer.concat([header, qname, tail])
}

describe('dns-filter · parseQuestion', () => {
  it('parses the name, type, and class', () => {
    const q = parseQuestion(query('ads.example.com', 1))
    expect(q).toMatchObject({ name: 'ads.example.com', qtype: 1, qclass: 1 })
  })

  it('lowercases the name', () => {
    expect(parseQuestion(query('ADS.Example.COM'))!.name).toBe('ads.example.com')
  })

  it('returns null for a too-short buffer', () => {
    expect(parseQuestion(Buffer.alloc(5))).toBeNull()
  })
})

describe('dns-filter · buildBlockedResponse', () => {
  it('answers A queries with 0.0.0.0 and preserves the query id', () => {
    const q = query('doubleclick.net', 1, 0xabcd)
    const parsed = parseQuestion(q)!
    const res = buildBlockedResponse(q, parsed)
    expect(res.readUInt16BE(0)).toBe(0xabcd) // id
    expect(res.readUInt16BE(2) & 0x8000).toBe(0x8000) // QR set
    expect(res.readUInt16BE(6)).toBe(1) // ANCOUNT
    const rdata = res.subarray(res.length - 4)
    expect([...rdata]).toEqual([0, 0, 0, 0]) // 0.0.0.0
  })

  it('answers AAAA queries with :: (16 zero bytes)', () => {
    const q = query('doubleclick.net', 28)
    const res = buildBlockedResponse(q, parseQuestion(q)!)
    expect(res.readUInt16BE(6)).toBe(1)
    expect([...res.subarray(res.length - 16)].every((b) => b === 0)).toBe(true)
  })

  it('returns NODATA (no answers) for other types', () => {
    const q = query('doubleclick.net', 15) // MX
    const res = buildBlockedResponse(q, parseQuestion(q)!)
    expect(res.readUInt16BE(6)).toBe(0)
  })
})

describe('dns-filter · TCP framing', () => {
  it('frames and de-frames a message', () => {
    const msg = Buffer.from([1, 2, 3, 4])
    const framed = frameTcp(msg)
    expect(framed.readUInt16BE(0)).toBe(4)
    const { messages, rest } = deframeTcp(framed)
    expect(messages).toHaveLength(1)
    expect([...messages[0]]).toEqual([1, 2, 3, 4])
    expect(rest.length).toBe(0)
  })

  it('leaves a partial trailing message in rest', () => {
    const framed = Buffer.concat([frameTcp(Buffer.from([9])), Buffer.from([0, 5, 1])])
    const { messages, rest } = deframeTcp(framed)
    expect(messages).toHaveLength(1)
    expect(rest.length).toBe(3)
  })
})

describe('dns-filter · filter lists', () => {
  it('parses hosts-format and plain domain lists, skipping comments/localhost', () => {
    const text = [
      '# comment',
      '0.0.0.0 ads.example.com',
      '127.0.0.1 tracker.example.net # inline',
      'plain-domain.example',
      '0.0.0.0 localhost',
      'invalid_no_dot',
    ].join('\n')
    expect(parseHostsList(text)).toEqual(['ads.example.com', 'tracker.example.net', 'plain-domain.example'])
  })

  it('domainAndParents enumerates suffixes', () => {
    expect(domainAndParents('a.b.example.com')).toEqual(['a.b.example.com', 'b.example.com', 'example.com', 'com'])
  })

  it('isBlocked matches exact and parent domains', () => {
    const set = new Set(['doubleclick.net', 'evil.example'])
    expect(isBlocked('doubleclick.net', set)).toBe(true)
    expect(isBlocked('stats.g.doubleclick.net', set)).toBe(true)
    expect(isBlocked('sub.evil.example', set)).toBe(true)
    expect(isBlocked('example.com', set)).toBe(false)
    expect(isBlocked('notdoubleclick.net', set)).toBe(false)
  })

  it('shouldBlockName supports isolation allowlist mode', () => {
    const allow = new Set(['googleapis.com', 'cloudflare.com'])
    expect(shouldBlockName('dns.google', allow, 'allowlist')).toBe(true)
    expect(shouldBlockName('fonts.googleapis.com', allow, 'allowlist')).toBe(false)
    expect(shouldBlockName('tracker.malware.test', allow, 'allowlist')).toBe(true)
    expect(shouldBlockName('tracker.malware.test', new Set(['tracker.malware.test']), 'blocklist')).toBe(true)
  })

  it('empty block set blocks nothing', () => {
    expect(isBlocked('anything.example', new Set())).toBe(false)
  })
})

describe('dns-filter · parseAnswerIps', () => {
  // Build a response for example.com with two A answers using name compression.
  function responseWithAs(ips: string[]): Buffer {
    const q = query('example.com', 1, 0x1234)
    const parsed = parseQuestion(q)!
    const header = Buffer.alloc(12)
    q.copy(header, 0, 0, 2)
    header.writeUInt16BE(0x8180, 2)
    header.writeUInt16BE(1, 4)
    header.writeUInt16BE(ips.length, 6)
    const question = q.subarray(12, parsed.questionEnd)
    const answers = ips.map((ip) => {
      const a = Buffer.alloc(16)
      a.writeUInt16BE(0xc00c, 0) // compressed name → question
      a.writeUInt16BE(1, 2) // A
      a.writeUInt16BE(1, 4) // IN
      a.writeUInt32BE(60, 6)
      a.writeUInt16BE(4, 10)
      const parts = ip.split('.').map((n) => parseInt(n, 10))
      a.writeUInt8(parts[0], 12); a.writeUInt8(parts[1], 13); a.writeUInt8(parts[2], 14); a.writeUInt8(parts[3], 15)
      return a
    })
    return Buffer.concat([header, question, ...answers])
  }

  it('extracts A record IPs from a response (with name compression)', () => {
    const msg = responseWithAs(['93.184.216.34', '1.2.3.4'])
    expect(parseAnswerIps(msg).map((a) => a.ip)).toEqual(['93.184.216.34', '1.2.3.4'])
  })

  it('returns empty for a query with no answers', () => {
    expect(parseAnswerIps(query('example.com'))).toEqual([])
  })
})

describe('dns-filter · typeName', () => {
  it('names common record types', () => {
    expect(typeName(1)).toBe('A')
    expect(typeName(28)).toBe('AAAA')
    expect(typeName(65)).toBe('HTTPS')
    expect(typeName(9999)).toBe('TYPE9999')
  })
})
