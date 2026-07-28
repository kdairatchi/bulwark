import { ipcMain } from 'electron'
import * as si from 'systeminformation'
import { IPC } from '../../shared/channels'
import type { NetworkEvent } from '../../shared/network-guard'
import type { ConnectionOverview, PortScanResult } from '../../shared/network-monitor'
import type { DnsResolverConfig, DnsResolverStats } from '../../shared/dns'
import type { NetworkRule } from '../../shared/policy'
import { buildIndicatorIndex, evaluateDestination, sanitizeIndicators } from '../services/network-guard'
import { buildConnectionOverview, parsePortSpec, scanPorts } from '../services/network-monitor'
import { dnsResolver } from '../services/dns-resolver'
import { loadRules, saveRules } from '../services/network-rules-store'
import { getFilterListsState, syncFilterLists } from '../services/filter-lists'
import { getEnabledListIds, setEnabledListIds } from '../services/filter-lists-store'
import type { FilterListsState } from '../../shared/filter-lists'
import { DnsEnforcement, buildEnforcementPlan } from '../services/dns-enforcement'
import type { EnforcementPlan, EnforcementStatus } from '../../shared/enforcement'
import { getGeoipStatus, syncGeoip, lookupCountry } from '../services/geoip'
import { evaluateRules } from '../services/policy-engine'
import type { GeoipStatus } from '../../shared/geoip'
import { cloudLog } from '../services/logger'
import { getPlatform } from '../platform'
import { refreshResolverBlocklist } from '../services/dns-blocklist-refresh'

/** Parse the resolver's bound port from its stats address (default 5353). */
function currentResolverPort(): number {
  const addr = dnsResolver.getStats().address
  const p = addr ? Number(addr.split(':')[1]) : NaN
  return Number.isFinite(p) ? p : 5353
}

const dnsEnforcement = new DnsEnforcement({
  isResolverRunning: () => dnsResolver.getStats().running,
  resolverPort: currentResolverPort,
  audit: (event, detail) => cloudLog('INFO', `[enforcement] ${event}${detail ? ': ' + detail : ''}`),
})

function refreshLocalBlocklistAndAnswerPolicy(): void {
  refreshResolverBlocklist()
  refreshResolverAnswerPolicy()
}

/**
 * Build the resolver's response-policy from IP/country block rules. Any resolved
 * A/AAAA answer whose IP (or its GeoIP country) matches a block rule is sinkholed
 * — enforcing IP/country rules at the DNS layer, no kernel firewall needed.
 */
function refreshResolverAnswerPolicy(): void {
  const rules = loadRules().filter((r) => r.enabled && r.action === 'block' && (r.match.ip || r.match.country))
  if (rules.length === 0) { dnsResolver.setAnswerPolicy(null); return }
  dnsResolver.setAnswerPolicy((ips: string[]) => {
    for (const ip of ips) {
      const country = lookupCountry(ip) ?? undefined
      const result = evaluateRules({ ip, country }, rules)
      if (result?.action === 'block') {
        return result.rule.match.country ? `country:${result.rule.match.country}` : 'ip-rule'
      }
    }
    return null
  })
}

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
  // Clean up any DNS enforcement orphaned by a previous run (restart/crash).
  void dnsEnforcement.reconcileOnStartup()

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
    return buildConnectionOverview(connections, listeningPorts, processNames, indicators, Date.now(), loadRules(), lookupCountry)
  })

  // ─── GeoIP (country lookup for country-based rules) ──────
  ipcMain.handle(IPC.GEOIP_STATUS, async (): Promise<GeoipStatus> => getGeoipStatus())
  ipcMain.handle(IPC.GEOIP_SYNC, async (): Promise<GeoipStatus> => syncGeoip())

  // ─── Secure DNS (DNS-over-TLS filtering resolver) ─────────
  ipcMain.handle(IPC.DNS_RESOLVER_START, async (_e, config?: Partial<DnsResolverConfig>): Promise<DnsResolverStats> => {
    refreshLocalBlocklistAndAnswerPolicy()
    return dnsResolver.start(config)
  })
  ipcMain.handle(IPC.DNS_RESOLVER_STOP, async (): Promise<DnsResolverStats> => {
    await dnsResolver.stop()
    return dnsResolver.getStats()
  })
  ipcMain.handle(IPC.DNS_RESOLVER_STATUS, async (): Promise<DnsResolverStats> => dnsResolver.getStats())

  // ─── Network rules ────────────────────────────────────────
  ipcMain.handle(IPC.NETWORK_RULES_GET, async (): Promise<NetworkRule[]> => loadRules())
  ipcMain.handle(IPC.NETWORK_RULES_SET, async (_e, rules: NetworkRule[]): Promise<NetworkRule[]> => {
    const saved = saveRules(rules)
    // Keep the running resolver's blocklist + response policy in sync with rules.
    refreshLocalBlocklistAndAnswerPolicy()
    return saved
  })

  // ─── Filter lists (Secure DNS blocklists) ────────────────
  ipcMain.handle(IPC.FILTER_LISTS_GET, async (): Promise<FilterListsState> => getFilterListsState(getEnabledListIds()))

  ipcMain.handle(IPC.FILTER_LISTS_SET_ENABLED, async (_e, ids: string[]): Promise<FilterListsState> => {
    const enabled = setEnabledListIds(Array.isArray(ids) ? ids : [])
    refreshLocalBlocklistAndAnswerPolicy()
    return getFilterListsState(enabled)
  })

  ipcMain.handle(IPC.FILTER_LISTS_SYNC, async (): Promise<FilterListsState> => {
    const enabled = getEnabledListIds()
    const state = await syncFilterLists(enabled)
    refreshLocalBlocklistAndAnswerPolicy()
    return state
  })

  // ─── System-wide DNS enforcement (privileged, reversible) ─
  ipcMain.handle(IPC.DNS_ENFORCE_STATUS, async (): Promise<EnforcementStatus> => dnsEnforcement.getStatus())
  ipcMain.handle(IPC.DNS_ENFORCE_PLAN, async (): Promise<EnforcementPlan> => buildEnforcementPlan(process.platform, currentResolverPort()))
  ipcMain.handle(IPC.DNS_ENFORCE_APPLY, async (): Promise<EnforcementStatus> => dnsEnforcement.apply())
  ipcMain.handle(IPC.DNS_ENFORCE_REVERT, async (): Promise<EnforcementStatus> => dnsEnforcement.revert('user'))

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
