import { describe, it, expect, afterEach } from 'vitest'
import net from 'net'
import {
  parsePortSpec,
  serviceForPort,
  scanPort,
  scanPorts,
  enrichConnections,
  groupByApp,
  buildConnectionOverview,
  TOP_PORTS,
} from './network-monitor'
import type { ActiveConnection } from '../platform/types'
import type { ThreatIndicator } from '../../shared/network-guard'

describe('network-monitor · parsePortSpec', () => {
  it('returns the well-known set for empty or "top"', () => {
    expect(parsePortSpec('')).toEqual(TOP_PORTS)
    expect(parsePortSpec('top')).toEqual(TOP_PORTS)
  })

  it('parses a comma list, sorted and deduped', () => {
    expect(parsePortSpec('443,22,80,22')).toEqual([22, 80, 443])
  })

  it('expands ranges', () => {
    expect(parsePortSpec('80-82')).toEqual([80, 81, 82])
  })

  it('combines ranges and lists', () => {
    expect(parsePortSpec('22, 80-81, 443')).toEqual([22, 80, 81, 443])
  })

  it('rejects invalid specs and out-of-range ports', () => {
    expect(() => parsePortSpec('abc')).toThrow()
    expect(() => parsePortSpec('0')).toThrow()
    expect(() => parsePortSpec('70000')).toThrow()
    expect(() => parsePortSpec('100-1')).toThrow()
  })
})

describe('network-monitor · serviceForPort', () => {
  it('names well-known ports', () => {
    expect(serviceForPort(443)).toBe('https')
    expect(serviceForPort(22)).toBe('ssh')
    expect(serviceForPort(5173)).toBe('vite')
  })
  it('returns unknown for unmapped ports', () => {
    expect(serviceForPort(64999)).toBe('unknown')
  })
})

describe('network-monitor · TCP connect scan (real listener)', () => {
  let server: net.Server | null = null
  afterEach(() => { if (server) { server.close(); server = null } })

  function listen(): Promise<number> {
    return new Promise((resolve) => {
      server = net.createServer()
      server.listen(0, '127.0.0.1', () => {
        const addr = server!.address()
        resolve(typeof addr === 'object' && addr ? addr.port : 0)
      })
    })
  }

  it('detects an open port and reports a closed one', async () => {
    const openPort = await listen()
    expect(await scanPort('127.0.0.1', openPort, 1000)).toBe(true)

    // A port that nothing is listening on should be closed/refused.
    const probe = await scanPort('127.0.0.1', 1, 300)
    expect(probe).toBe(false)
  })

  it('scanPorts returns the open port with its service label', async () => {
    const openPort = await listen()
    const result = await scanPorts('127.0.0.1', [openPort, 2, 3], { timeoutMs: 500 })
    expect(result.host).toBe('127.0.0.1')
    expect(result.scanned).toBe(3)
    expect(result.openPorts.map((p) => p.port)).toContain(openPort)
    expect(result.durationMs).toBeGreaterThanOrEqual(0)
  })
})

describe('network-monitor · connection enrichment + grouping', () => {
  const connections: ActiveConnection[] = [
    { remoteAddress: '93.184.216.34', remotePort: 443, localPort: 50001, pid: 100 },
    { remoteAddress: 'evil-c2.example', remotePort: 443, localPort: 50002, pid: 100 },
    { remoteAddress: '8.8.8.8', remotePort: 53, localPort: 50003, pid: 200 },
  ]
  const names = new Map<number, string>([[100, 'firefox'], [200, 'systemd-resolved']])
  const indicators: ThreatIndicator[] = [
    { value: 'evil-c2.example', type: 'domain', category: 'c2', confidence: 0.97 },
  ]

  it('attaches process names and guard verdicts', () => {
    const records = enrichConnections(connections, names, indicators)
    expect(records[0]).toMatchObject({ process: 'firefox', decision: 'allow', reason: 'no_match' })
    expect(records[1]).toMatchObject({ process: 'firefox', decision: 'block', reason: 'known_c2', category: 'c2' })
    expect(records[2].process).toBe('systemd-resolved')
  })

  it('falls back to "unknown" when the pid has no name', () => {
    const records = enrichConnections(
      [{ remoteAddress: '1.1.1.1', remotePort: 443, localPort: 1, pid: 999 }],
      names,
      [],
    )
    expect(records[0].process).toBe('unknown')
  })

  it('groups by app and surfaces the worst decision first', () => {
    const groups = groupByApp(enrichConnections(connections, names, indicators))
    // firefox (has a block) should sort ahead of systemd-resolved (all allow)
    expect(groups[0].app).toBe('firefox')
    expect(groups[0].worst).toBe('block')
    expect(groups[0].count).toBe(2)
    expect(groups[1].worst).toBe('allow')
  })

  it('builds an overview with counts and sorted listening ports', async () => {
    const overview = await buildConnectionOverview(connections, [443, 22, 80], names, indicators, Date.parse('2026-07-28T00:00:00Z'))
    expect(overview.totalConnections).toBe(3)
    expect(overview.blocked).toBe(1)
    expect(overview.alerted).toBe(0)
    expect(overview.listeningPorts).toEqual([22, 80, 443])
    expect(overview.generatedAt).toBe('2026-07-28T00:00:00.000Z')
  })
})
