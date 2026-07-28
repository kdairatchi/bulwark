// Network monitor: a live, per-application connection view + an on-device TCP
// port scanner. Portmaster-inspired ("monitor and control all network
// connections"), but local-first and metadata-only.
//
// The port scanner is a plain TCP connect scan (net.connect) — no raw sockets,
// no root — so it works cross-platform in the Electron main process.

import net from 'net'
import type { ActiveConnection } from '../platform/types'
import type { ThreatIndicator, NetworkDecision } from '../../shared/network-guard'
import type {
  AppConnections,
  ConnectionOverview,
  ConnectionRecord,
  OpenPort,
  PortScanResult,
} from '../../shared/network-monitor'
import { buildIndicatorIndex, evaluateDestination } from './network-guard'

// ─── Port ↔ service naming ──────────────────────────────────

const PORT_SERVICES: Record<number, string> = {
  20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  67: 'dhcp', 68: 'dhcp', 80: 'http', 110: 'pop3', 111: 'rpcbind', 123: 'ntp',
  135: 'msrpc', 139: 'netbios', 143: 'imap', 161: 'snmp', 389: 'ldap',
  443: 'https', 445: 'smb', 465: 'smtps', 514: 'syslog', 587: 'submission',
  631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
  1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 2375: 'docker',
  2376: 'docker-tls', 3000: 'dev-http', 3306: 'mysql', 3389: 'rdp',
  5432: 'postgresql', 5900: 'vnc', 5901: 'vnc-1', 5902: 'vnc-2', 5173: 'vite',
  6379: 'redis', 8080: 'http-alt', 8443: 'https-alt', 9090: 'prometheus',
  9100: 'node-exporter', 9200: 'elasticsearch', 27017: 'mongodb',
}

export function serviceForPort(port: number): string {
  return PORT_SERVICES[port] ?? 'unknown'
}

/** A small, useful default set of well-known ports. */
export const TOP_PORTS: number[] = [
  20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
  514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000,
  3306, 3389, 5173, 5432, 5900, 5901, 5902, 6379, 8080, 8443, 9090, 9100, 9200,
  27017,
]

const MAX_PORTS = 10_000

/**
 * Parse a port spec into a sorted, de-duplicated, validated port list.
 * Supports: "top" (well-known set), "22,80,443", "1-1024", and combinations.
 * Throws on invalid input so callers can surface a clear error.
 */
export function parsePortSpec(spec: string): number[] {
  const trimmed = (spec || '').trim().toLowerCase()
  if (!trimmed || trimmed === 'top') return [...TOP_PORTS]

  const ports = new Set<number>()
  for (const part of trimmed.split(',').map((p) => p.trim()).filter(Boolean)) {
    const range = part.match(/^(\d+)-(\d+)$/)
    if (range) {
      const start = parseInt(range[1], 10)
      const end = parseInt(range[2], 10)
      if (start < 1 || end > 65535 || start > end) throw new Error(`Invalid port range: ${part}`)
      for (let p = start; p <= end; p++) {
        ports.add(p)
        if (ports.size > MAX_PORTS) throw new Error(`Too many ports (max ${MAX_PORTS})`)
      }
    } else if (/^\d+$/.test(part)) {
      const p = parseInt(part, 10)
      if (p < 1 || p > 65535) throw new Error(`Invalid port: ${part}`)
      ports.add(p)
    } else {
      throw new Error(`Invalid port spec: ${part}`)
    }
  }
  if (ports.size === 0) throw new Error('No valid ports specified')
  return [...ports].sort((a, b) => a - b)
}

/** Probe a single TCP port with a connect + timeout. Resolves true if open. */
export function scanPort(host: string, port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false
    const done = (open: boolean) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(open)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done(true))
    socket.once('timeout', () => done(false))
    socket.once('error', () => done(false))
    try {
      socket.connect(port, host)
    } catch {
      done(false)
    }
  })
}

/** Run a connect scan across ports with bounded concurrency. */
export async function scanPorts(
  host: string,
  ports: number[],
  opts: { timeoutMs?: number; concurrency?: number } = {},
): Promise<PortScanResult> {
  const timeoutMs = opts.timeoutMs ?? 500
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? 200, 500))
  const started = Date.now()
  const open: OpenPort[] = []

  let cursor = 0
  async function worker(): Promise<void> {
    while (cursor < ports.length) {
      const port = ports[cursor++]
      if (await scanPort(host, port, timeoutMs)) {
        open.push({ port, service: serviceForPort(port) })
      }
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, ports.length) }, () => worker())
  await Promise.all(workers)

  open.sort((a, b) => a.port - b.port)
  return { host, openPorts: open, scanned: ports.length, durationMs: Date.now() - started }
}

// ─── Live connection monitor ────────────────────────────────

const DECISION_RANK: Record<NetworkDecision, number> = { allow: 0, alert: 1, block: 2 }

function worstDecision(records: ConnectionRecord[]): NetworkDecision {
  return records.reduce<NetworkDecision>(
    (worst, r) => (DECISION_RANK[r.decision] > DECISION_RANK[worst] ? r.decision : worst),
    'allow',
  )
}

/** Enrich raw connections with process names + a Network Guard verdict. */
export function enrichConnections(
  connections: ActiveConnection[],
  processNames: Map<number, string>,
  indicators: ThreatIndicator[],
): ConnectionRecord[] {
  const index = buildIndicatorIndex(indicators)
  return connections.map((c) => {
    const event = evaluateDestination({ destination: c.remoteAddress, port: c.remotePort, protocol: 'tcp' }, index)
    return {
      remoteAddress: c.remoteAddress,
      remotePort: c.remotePort,
      localPort: c.localPort,
      pid: c.pid,
      process: (c.pid != null && processNames.get(c.pid)) || 'unknown',
      decision: event.decision,
      reason: event.reason,
      category: event.category,
      confidence: event.confidence,
    }
  })
}

/** Group connection records by owning application. */
export function groupByApp(records: ConnectionRecord[]): AppConnections[] {
  const byApp = new Map<string, ConnectionRecord[]>()
  for (const r of records) {
    const key = `${r.process}#${r.pid ?? 'na'}`
    const list = byApp.get(key) ?? []
    list.push(r)
    byApp.set(key, list)
  }
  const apps: AppConnections[] = []
  for (const list of byApp.values()) {
    apps.push({
      app: list[0].process,
      pid: list[0].pid,
      count: list.length,
      worst: worstDecision(list),
      connections: list.sort((a, b) => DECISION_RANK[b.decision] - DECISION_RANK[a.decision]),
    })
  }
  // Riskiest apps first, then by connection count.
  return apps.sort((a, b) => DECISION_RANK[b.worst] - DECISION_RANK[a.worst] || b.count - a.count)
}

/** Build a full connection overview from live platform data. */
export async function buildConnectionOverview(
  connections: ActiveConnection[],
  listeningPorts: number[],
  processNames: Map<number, string>,
  indicators: ThreatIndicator[],
  now: number = Date.now(),
): Promise<ConnectionOverview> {
  const records = enrichConnections(connections, processNames, indicators)
  const apps = groupByApp(records)
  return {
    apps,
    totalConnections: records.length,
    blocked: records.filter((r) => r.decision === 'block').length,
    alerted: records.filter((r) => r.decision === 'alert').length,
    listeningPorts: [...listeningPorts].sort((a, b) => a - b),
    generatedAt: new Date(now).toISOString(),
  }
}
