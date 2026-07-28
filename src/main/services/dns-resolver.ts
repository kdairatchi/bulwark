// Local DNS-over-TLS filtering resolver.
//
// - Listens on UDP + TCP (loopback).
// - Blocks names present in the filter set (tracker/malware lists) with a
//   sinkhole/NODATA answer — no upstream query is made for blocked names.
// - Forwards everything else to an upstream resolver over DNS-over-TLS (853),
//   so queries leave the machine encrypted.
//
// Pointing the OS/browser resolver at this server makes the filtering + DoT
// system-wide; that redirection step is privileged and lives outside this class.

import dgram from 'dgram'
import net from 'net'
import tls from 'tls'
import {
  parseQuestion,
  buildBlockedResponse,
  frameTcp,
  deframeTcp,
  isBlocked,
  typeName,
  parseAnswerIps,
} from './dns-filter'
import type { DnsResolverConfig, DnsResolverStats, DnsQueryLogEntry } from '../../shared/dns'
import { DEFAULT_DNS_CONFIG } from '../../shared/dns'

const UPSTREAM_TIMEOUT_MS = 5000
const MAX_LOG = 100

export class DnsResolver {
  private udp: dgram.Socket | null = null
  private tcp: net.Server | null = null
  private config: DnsResolverConfig = { ...DEFAULT_DNS_CONFIG }
  private blockSet: Set<string> = new Set()
  private running = false
  private startedAt: string | null = null
  /** Response-policy hook: given resolved IPs, return a block reason or null. */
  private answerPolicy: ((ips: string[]) => string | null) | null = null

  private totalQueries = 0
  private blockedQueries = 0
  private forwardedQueries = 0
  private failedQueries = 0
  private recent: DnsQueryLogEntry[] = []

  /** Replace the filter-list block set. */
  setBlocklist(domains: Iterable<string>): void {
    this.blockSet = new Set([...domains].map((d) => d.toLowerCase().replace(/\.$/, '')))
  }

  /**
   * Set a response-policy hook. When forwarding, the resolved A/AAAA answers are
   * passed to it; a non-null return (reason) sinkholes the response — enforcing
   * IP- and country-block rules at the DNS layer without a kernel firewall.
   */
  setAnswerPolicy(fn: ((ips: string[]) => string | null) | null): void {
    this.answerPolicy = fn
  }

  getStats(): DnsResolverStats {
    return {
      running: this.running,
      address: this.running ? `${this.config.host}:${this.config.port}` : null,
      upstream: `${this.config.upstreamHost}:${this.config.upstreamPort} (DoT)`,
      totalQueries: this.totalQueries,
      blockedQueries: this.blockedQueries,
      forwardedQueries: this.forwardedQueries,
      failedQueries: this.failedQueries,
      filterListSize: this.blockSet.size,
      recent: [...this.recent],
      startedAt: this.startedAt,
    }
  }

  async start(config?: Partial<DnsResolverConfig>): Promise<DnsResolverStats> {
    if (this.running) return this.getStats()
    this.config = { ...DEFAULT_DNS_CONFIG, ...config }

    await new Promise<void>((resolve, reject) => {
      const udp = dgram.createSocket('udp4')
      udp.on('error', reject)
      udp.on('message', (msg, rinfo) => this.handleUdp(udp, msg, rinfo))
      udp.bind(this.config.port, this.config.host, () => {
        udp.removeListener('error', reject)
        // Resolve an OS-assigned (port 0) binding to the concrete port so TCP
        // binds to the same one and stats report the real address.
        this.config.port = udp.address().port
        this.udp = udp
        resolve()
      })
    })

    await new Promise<void>((resolve, reject) => {
      const tcp = net.createServer((socket) => this.handleTcp(socket))
      tcp.on('error', reject)
      tcp.listen(this.config.port, this.config.host, () => {
        tcp.removeListener('error', reject)
        this.tcp = tcp
        resolve()
      })
    })

    this.running = true
    this.startedAt = new Date().toISOString()
    return this.getStats()
  }

  async stop(): Promise<void> {
    this.running = false
    this.startedAt = null
    if (this.udp) { this.udp.close(); this.udp = null }
    if (this.tcp) { await new Promise<void>((r) => this.tcp!.close(() => r())); this.tcp = null }
  }

  // ─── Request handling ────────────────────────────────────

  private log(entry: DnsQueryLogEntry): void {
    this.recent.unshift(entry)
    if (this.recent.length > MAX_LOG) this.recent.length = MAX_LOG
  }

  private async handleUdp(sock: dgram.Socket, msg: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
    const response = await this.resolve(msg)
    if (response) sock.send(response, rinfo.port, rinfo.address)
  }

  private handleTcp(socket: net.Socket): void {
    let buffer = Buffer.alloc(0)
    socket.on('data', async (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      const { messages, rest } = deframeTcp(buffer)
      buffer = rest
      for (const m of messages) {
        const response = await this.resolve(m)
        if (response) socket.write(frameTcp(response))
      }
    })
    socket.on('error', () => socket.destroy())
    socket.setTimeout(30_000, () => socket.destroy())
  }

  /** Core decision: block via filter set, else forward over DoT. */
  private async resolve(query: Buffer): Promise<Buffer | null> {
    this.totalQueries++
    const q = parseQuestion(query)
    if (!q) { this.failedQueries++; return null }

    const ts = new Date().toISOString()
    if (isBlocked(q.name, this.blockSet)) {
      this.blockedQueries++
      this.log({ name: q.name, type: typeName(q.qtype), blocked: true, via: 'filter-list', timestamp: ts })
      return buildBlockedResponse(query, q)
    }

    try {
      const response = await this.forwardDot(query)
      // Response policy: sinkhole if a resolved IP matches an IP/country block rule.
      if (this.answerPolicy) {
        const ips = parseAnswerIps(response).map((a) => a.ip)
        if (ips.length > 0) {
          const reason = this.answerPolicy(ips)
          if (reason) {
            this.blockedQueries++
            this.log({ name: q.name, type: typeName(q.qtype), blocked: true, via: reason, timestamp: ts })
            return buildBlockedResponse(query, q)
          }
        }
      }
      this.forwardedQueries++
      this.log({ name: q.name, type: typeName(q.qtype), blocked: false, via: this.config.upstreamHost, timestamp: ts })
      return response
    } catch {
      this.failedQueries++
      this.log({ name: q.name, type: typeName(q.qtype), blocked: false, via: 'upstream-error', timestamp: ts })
      return null
    }
  }

  /** Forward one query to the upstream resolver over DNS-over-TLS. */
  private forwardDot(query: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: this.config.upstreamHost,
        port: this.config.upstreamPort,
        servername: this.config.upstreamServerName,
      })
      let buffer = Buffer.alloc(0)
      let settled = false
      const finish = (err: Error | null, res?: Buffer) => {
        if (settled) return
        settled = true
        socket.destroy()
        if (err) reject(err); else resolve(res!)
      }
      socket.setTimeout(UPSTREAM_TIMEOUT_MS, () => finish(new Error('upstream timeout')))
      socket.on('secureConnect', () => socket.write(frameTcp(query)))
      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk])
        const { messages } = deframeTcp(buffer)
        if (messages.length > 0) finish(null, messages[0])
      })
      socket.on('error', (err) => finish(err))
      socket.on('close', () => finish(new Error('upstream closed')))
    })
  }
}

export const dnsResolver = new DnsResolver()
