import { create } from 'zustand'
import type { NetworkEvent, ThreatIndicator } from '@shared/network-guard'

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
}))
