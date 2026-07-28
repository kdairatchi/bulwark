import { create } from 'zustand'
import type { NetworkEvent, ThreatIndicator } from '@shared/network-guard'
import type { ConnectionOverview, PortScanResult } from '@shared/network-monitor'
import type { DnsResolverStats } from '@shared/dns'
import type { NetworkRule } from '@shared/policy'
import type { FilterListsState } from '@shared/filter-lists'
import type { EnforcementStatus } from '@shared/enforcement'

// A small, clearly-labeled EXAMPLE feed so the checker is usable out of the box.
// These use RFC 2606 reserved names — they are placeholders that demonstrate the
// engine, not real threat intelligence. Replace with a real feed (URLhaus,
// ThreatFox, abuse.ch, …) in production.
export const EXAMPLE_FEED: ThreatIndicator[] = [
  { value: 'evil-c2.example', type: 'domain', category: 'c2', source: 'example', confidence: 0.97 },
  { value: 'login-secure.phish.example', type: 'domain', category: 'phishing', source: 'example' },
  { value: 'proxynode.example', type: 'domain', category: 'residential_proxy', source: 'example' },
  { value: 'pool.mine.example', type: 'domain', category: 'cryptomining', source: 'example' },
  { value: '198.51.100.0/24', type: 'cidr', category: 'botnet', source: 'example' },
]

interface HistoryItem {
  event: NetworkEvent
}

interface NetworkGuardState {
  feedText: string
  checking: boolean
  error: string | null
  result: NetworkEvent | null
  history: HistoryItem[]
  setFeedText: (text: string) => void
  check: (destination: string) => Promise<void>
  // Live connection monitor
  overview: ConnectionOverview | null
  monitorLoading: boolean
  refreshConnections: () => Promise<void>
  // Port scanner
  scanResult: PortScanResult | null
  scanning: boolean
  scanPorts: (host: string, ports: string) => Promise<void>
  // Secure DNS resolver
  dns: DnsResolverStats | null
  dnsBusy: boolean
  dnsStatus: () => Promise<void>
  dnsToggle: () => Promise<void>
  // Rules
  rules: NetworkRule[]
  loadRules: () => Promise<void>
  saveRules: (rules: NetworkRule[]) => Promise<void>
  // Filter lists
  filterLists: FilterListsState | null
  filterSyncing: boolean
  loadFilterLists: () => Promise<void>
  toggleFilterList: (id: string, enabled: boolean) => Promise<void>
  syncFilterLists: () => Promise<void>
  // System-wide enforcement
  enforcement: EnforcementStatus | null
  enforceBusy: boolean
  loadEnforcement: () => Promise<void>
  toggleEnforcement: () => Promise<void>
}

function parseFeed(text: string): ThreatIndicator[] {
  const trimmed = text.trim()
  if (!trimmed) return []
  const parsed = JSON.parse(trimmed)
  if (Array.isArray(parsed)) return parsed as ThreatIndicator[]
  if (parsed && Array.isArray(parsed.indicators)) return parsed.indicators as ThreatIndicator[]
  return []
}

export const useNetworkGuardStore = create<NetworkGuardState>((set, get) => ({
  feedText: JSON.stringify(EXAMPLE_FEED, null, 2),
  checking: false,
  error: null,
  result: null,
  history: [],
  setFeedText: (feedText) => set({ feedText }),
  check: async (destination) => {
    const target = destination.trim()
    if (!target) {
      set({ error: 'Enter a domain or IP to check.' })
      return
    }
    let indicators: ThreatIndicator[]
    try {
      indicators = parseFeed(get().feedText)
    } catch {
      set({ error: 'Indicator feed is not valid JSON.' })
      return
    }
    set({ checking: true, error: null })
    try {
      const event = await window.kudu.networkGuardCheck({ destination: target, indicators })
      set((s) => ({ result: event, checking: false, history: [{ event }, ...s.history].slice(0, 12) }))
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Check failed', checking: false })
    }
  },

  overview: null,
  monitorLoading: false,
  refreshConnections: async () => {
    let indicators: ThreatIndicator[] = []
    try { indicators = parseFeed(get().feedText) } catch { /* use empty feed if invalid */ }
    set({ monitorLoading: true })
    try {
      const overview = await window.kudu.networkMonitorList(indicators)
      set({ overview, monitorLoading: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Failed to load connections', monitorLoading: false })
    }
  },

  scanResult: null,
  scanning: false,
  scanPorts: async (host, ports) => {
    set({ scanning: true, scanResult: null })
    try {
      const scanResult = await window.kudu.networkPortScan({ host: host.trim() || '127.0.0.1', ports })
      set({ scanResult, scanning: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Scan failed', scanning: false })
    }
  },

  dns: null,
  dnsBusy: false,
  dnsStatus: async () => {
    try { set({ dns: await window.kudu.dnsResolverStatus() }) } catch { /* ignore */ }
  },
  dnsToggle: async () => {
    set({ dnsBusy: true })
    try {
      const running = get().dns?.running
      const dns = running ? await window.kudu.dnsResolverStop() : await window.kudu.dnsResolverStart()
      set({ dns, dnsBusy: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'DNS resolver error', dnsBusy: false })
    }
  },

  rules: [],
  loadRules: async () => {
    try { set({ rules: await window.kudu.networkRulesGet() }) } catch { /* ignore */ }
  },
  saveRules: async (rules) => {
    try { set({ rules: await window.kudu.networkRulesSet(rules) }) }
    catch (err) { set({ error: err instanceof Error ? err.message : 'Failed to save rules' }) }
  },

  filterLists: null,
  filterSyncing: false,
  loadFilterLists: async () => {
    try { set({ filterLists: await window.kudu.filterListsGet() }) } catch { /* ignore */ }
  },
  toggleFilterList: async (id, enabled) => {
    const current = get().filterLists?.lists ?? []
    const ids = current.filter((l) => (l.id === id ? enabled : l.enabled)).map((l) => l.id)
    try { set({ filterLists: await window.kudu.filterListsSetEnabled(ids) }) }
    catch (err) { set({ error: err instanceof Error ? err.message : 'Failed to update lists' }) }
  },
  syncFilterLists: async () => {
    set({ filterSyncing: true })
    try { set({ filterLists: await window.kudu.filterListsSync(), filterSyncing: false }) }
    catch (err) { set({ error: err instanceof Error ? err.message : 'Sync failed', filterSyncing: false }) }
  },

  enforcement: null,
  enforceBusy: false,
  loadEnforcement: async () => {
    try { set({ enforcement: await window.kudu.dnsEnforceStatus() }) } catch { /* ignore */ }
  },
  toggleEnforcement: async () => {
    set({ enforceBusy: true })
    try {
      const enforcing = get().enforcement?.enforcing
      const status = enforcing ? await window.kudu.dnsEnforceRevert() : await window.kudu.dnsEnforceApply()
      set({ enforcement: status, enforceBusy: false })
    } catch (err) {
      set({ error: err instanceof Error ? err.message : 'Enforcement error', enforceBusy: false })
    }
  },
}))
