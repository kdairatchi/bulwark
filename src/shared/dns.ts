// Types for the local DNS-over-TLS filtering resolver.
// It blocks tracker/malware domains from filter lists (system-wide when the OS
// is pointed at it) and forwards everything else encrypted over DNS-over-TLS.

export interface DnsResolverConfig {
  /** Loopback bind address. */
  host: string
  /** Bind port (53 needs privileges; dev/default uses a high port). */
  port: number
  /** Upstream DoT resolver host (e.g. Cloudflare 1.1.1.1, Quad9 9.9.9.9). */
  upstreamHost: string
  /** Upstream DoT port (standard 853). */
  upstreamPort: number
  /** TLS SNI / cert name for the upstream (e.g. cloudflare-dns.com). */
  upstreamServerName: string
}

export interface DnsQueryLogEntry {
  name: string
  type: string
  blocked: boolean
  /** 'filter-list', 'rule', or the upstream host when forwarded. */
  via: string
  timestamp: string
}

export interface DnsResolverStats {
  running: boolean
  address: string | null
  upstream: string
  totalQueries: number
  blockedQueries: number
  forwardedQueries: number
  failedQueries: number
  filterListSize: number
  recent: DnsQueryLogEntry[]
  startedAt: string | null
}

export const DEFAULT_DNS_CONFIG: DnsResolverConfig = {
  host: '127.0.0.1',
  port: 5353,
  upstreamHost: '1.1.1.1',
  upstreamPort: 853,
  upstreamServerName: 'cloudflare-dns.com',
}
