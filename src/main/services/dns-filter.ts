// Pure DNS wire-format helpers + filter-list matching for the local resolver.
// No I/O here so it is fully unit-testable; the socket server lives in
// dns-resolver.ts.

/** DNS record type numbers we care about. */
export const DNS_TYPE = { A: 1, AAAA: 28 } as const

export function typeName(qtype: number): string {
  switch (qtype) {
    case 1: return 'A'
    case 2: return 'NS'
    case 5: return 'CNAME'
    case 6: return 'SOA'
    case 12: return 'PTR'
    case 15: return 'MX'
    case 16: return 'TXT'
    case 28: return 'AAAA'
    case 33: return 'SRV'
    case 65: return 'HTTPS'
    default: return `TYPE${qtype}`
  }
}

export interface ParsedQuestion {
  name: string
  qtype: number
  qclass: number
  /** Byte offset immediately after the question section. */
  questionEnd: number
}

/**
 * Parse the first question from a DNS message. Questions never use name
 * compression, so a straight label walk is safe. Returns null on malformed input.
 */
export function parseQuestion(msg: Buffer): ParsedQuestion | null {
  if (msg.length < 12) return null
  const qdcount = msg.readUInt16BE(4)
  if (qdcount < 1) return null

  let offset = 12
  const labels: string[] = []
  while (offset < msg.length) {
    const len = msg[offset]
    if (len === 0) { offset += 1; break }
    // Compression pointers are invalid in a question name.
    if ((len & 0xc0) !== 0) return null
    offset += 1
    if (offset + len > msg.length) return null
    labels.push(msg.subarray(offset, offset + len).toString('ascii'))
    offset += len
  }
  if (offset + 4 > msg.length) return null
  const qtype = msg.readUInt16BE(offset)
  const qclass = msg.readUInt16BE(offset + 2)
  return { name: labels.join('.').toLowerCase(), qtype, qclass, questionEnd: offset + 4 }
}

/**
 * Build a response that blocks a name:
 *  - A     → 0.0.0.0
 *  - AAAA  → ::
 *  - other → NODATA (no answer records) so resolution still fails cleanly.
 * The question section is echoed and the query ID preserved.
 */
export function buildBlockedResponse(query: Buffer, q: ParsedQuestion): Buffer {
  const header = Buffer.alloc(12)
  query.copy(header, 0, 0, 2) // copy query ID
  // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=(from query), RA=1, RCODE=0
  const rd = (query.readUInt16BE(2) & 0x0100) !== 0
  header.writeUInt16BE(0x8000 | (rd ? 0x0100 : 0) | 0x0080, 2)
  header.writeUInt16BE(1, 4) // QDCOUNT

  const question = query.subarray(12, q.questionEnd)

  let answer = Buffer.alloc(0)
  if (q.qtype === DNS_TYPE.A || q.qtype === DNS_TYPE.AAAA) {
    const rdata = q.qtype === DNS_TYPE.A ? Buffer.alloc(4) : Buffer.alloc(16) // zeros = 0.0.0.0 / ::
    answer = Buffer.alloc(12 + rdata.length)
    answer.writeUInt16BE(0xc00c, 0) // name pointer → offset 12 (question)
    answer.writeUInt16BE(q.qtype, 2)
    answer.writeUInt16BE(1, 4) // class IN
    answer.writeUInt32BE(60, 6) // TTL
    answer.writeUInt16BE(rdata.length, 10)
    rdata.copy(answer, 12)
    header.writeUInt16BE(1, 6) // ANCOUNT
  } else {
    header.writeUInt16BE(0, 6) // NODATA
  }
  return Buffer.concat([header, question, answer])
}

/** Frame a DNS message for TCP/DoT transport (2-byte big-endian length prefix). */
export function frameTcp(msg: Buffer): Buffer {
  const len = Buffer.alloc(2)
  len.writeUInt16BE(msg.length, 0)
  return Buffer.concat([len, msg])
}

/**
 * Pull complete DNS messages out of a TCP/DoT stream buffer.
 * Returns the decoded messages and the leftover bytes.
 */
export function deframeTcp(buf: Buffer): { messages: Buffer[]; rest: Buffer } {
  const messages: Buffer[] = []
  let offset = 0
  while (offset + 2 <= buf.length) {
    const len = buf.readUInt16BE(offset)
    if (offset + 2 + len > buf.length) break
    messages.push(buf.subarray(offset + 2, offset + 2 + len))
    offset += 2 + len
  }
  return { messages, rest: buf.subarray(offset) }
}

/**
 * Parse a hosts-style or plain-domain filter list into a domain array.
 * Accepts StevenBlack/hagezi hosts format ("0.0.0.0 domain", "127.0.0.1 domain")
 * and plain "domain" lines. Ignores comments and localhost entries.
 */
export function parseHostsList(text: string): string[] {
  const domains: string[] = []
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.split('#')[0].trim()
    if (!line) continue
    const parts = line.split(/\s+/)
    // "0.0.0.0 domain" / "127.0.0.1 domain" → take the domain; else plain domain.
    const candidate = parts.length >= 2 ? parts[1] : parts[0]
    const domain = candidate.toLowerCase().replace(/\.$/, '')
    if (!domain || domain === 'localhost' || domain === 'localhost.localdomain') continue
    if (!/^[a-z0-9.-]+$/.test(domain) || !domain.includes('.')) continue
    domains.push(domain)
  }
  return domains
}

/**
 * A small built-in starter blocklist of well-known ad/tracker/telemetry hosts,
 * so filtering works out of the box (like Portmaster's default lists). These are
 * real, widely-blocked tracker domains — replace/extend with full filter lists
 * (StevenBlack, hagezi, …) via parseHostsList for production coverage.
 */
export const STARTER_BLOCKLIST: string[] = [
  'doubleclick.net',
  'googleadservices.com',
  'google-analytics.com',
  'googlesyndication.com',
  'googletagmanager.com',
  'adservice.google.com',
  'ads.yahoo.com',
  'analytics.twitter.com',
  'ads.facebook.com',
  'graph.facebook.com',
  'connect.facebook.net',
  'app-measurement.com',
  'scorecardresearch.com',
  'adnxs.com',
  'criteo.com',
  'taboola.com',
  'outbrain.com',
  'mixpanel.com',
  'hotjar.com',
  'segment.io',
]

/** Enumerate a domain and its parents: a.b.c → [a.b.c, b.c, c]. */
export function domainAndParents(domain: string): string[] {
  const labels = domain.split('.')
  const out: string[] = []
  for (let i = 0; i < labels.length; i++) out.push(labels.slice(i).join('.'))
  return out
}

/** True if the name or any parent domain is in the block set. */
export function isBlocked(name: string, blockSet: Set<string>): boolean {
  if (blockSet.size === 0) return false
  const normalized = name.toLowerCase().replace(/\.$/, '')
  for (const candidate of domainAndParents(normalized)) {
    if (blockSet.has(candidate)) return true
  }
  return false
}
