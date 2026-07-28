import { ipcMain } from 'electron'
import * as si from 'systeminformation'
import { IPC } from '../../shared/channels'
import type { NetworkEvent } from '../../shared/network-guard'
import type { ConnectionOverview, PortScanResult } from '../../shared/network-monitor'
import { buildIndicatorIndex, evaluateDestination, sanitizeIndicators } from '../services/network-guard'
import { buildConnectionOverview, parsePortSpec, scanPorts } from '../services/network-monitor'
import { getPlatform } from '../platform'

export interface NetworkGuardCheckRequest {
  destination: string
  indicators?: unknown
  port?: number
  protocol?: 'tcp' | 'udp'
}

export interface PortScanRequest {
  host?: string
  ports?: string
  timeoutMs?: number
}

// Local-first: destination metadata is matched against a caller-supplied
// indicator feed entirely on-device. No payloads, no network calls.
export function registerNetworkGuardIpc(): void {
  ipcMain.handle(IPC.NETWORK_GUARD_CHECK, async (_e, req: NetworkGuardCheckRequest): Promise<NetworkEvent> => {
    const destination = typeof req?.destination === 'string' ? req.destination.trim() : ''
    if (!destination) throw new Error('A destination (domain or IP) is required')
    const indicators = sanitizeIndicators(req?.indicators)
    const index = buildIndicatorIndex(indicators)
    return evaluateDestination(
      { destination, port: req?.port, protocol: req?.protocol },
      index,
    )
  })

  // Live per-application connection view, each evaluated by Network Guard.
  ipcMain.handle(IPC.NETWORK_MONITOR_LIST, async (_e, indicatorsRaw?: unknown): Promise<ConnectionOverview> => {
    const platform = getPlatform()
    const [connections, listeningPorts, procInfo] = await Promise.all([
      platform.network.getEstablishedConnections(),
      platform.network.getListeningPorts().catch(() => [] as number[]),
      si.processes().catch(() => ({ list: [] as { pid: number; name: string }[] })),
    ])
    const processNames = new Map<number, string>()
    for (const p of procInfo.list as { pid: number; name: string }[]) {
      processNames.set(p.pid, p.name)
    }
    const indicators = sanitizeIndicators(indicatorsRaw)
    return buildConnectionOverview(connections, listeningPorts, processNames, indicators)
  })

  // On-device TCP connect scanner. Defaults to localhost.
  ipcMain.handle(IPC.NETWORK_PORT_SCAN, async (_e, req: PortScanRequest): Promise<PortScanResult> => {
    const host = (typeof req?.host === 'string' && req.host.trim()) || '127.0.0.1'
    try {
      const ports = parsePortSpec(typeof req?.ports === 'string' ? req.ports : 'top')
      const timeoutMs = typeof req?.timeoutMs === 'number' ? Math.max(50, Math.min(req.timeoutMs, 3000)) : 500
      return await scanPorts(host, ports, { timeoutMs })
    } catch (err) {
      return {
        host,
        openPorts: [],
        scanned: 0,
        durationMs: 0,
        error: err instanceof Error ? err.message : 'Invalid scan request',
      }
    }
  })
}
