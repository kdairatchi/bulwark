// Network Guard engine — pure, deterministic indicator matching + decision.
//
// Pipeline (see docs/architecture/overview.md#detection--vulnerability-pipelines):
//   normalize → indicator lookup → decision + confidence → NetworkEvent
//
// CIDR/IP parsing is reused from the threat monitor to avoid a second
// implementation of the fiddly IPv4/IPv6 math.

import { parseCidr, ipMatchesCidr, ipv4ToNumber, ipv6ToBigInt } from './threat-monitor'
import type {
  DestinationInput,
  IndicatorMatch,
  NetworkDecision,
  NetworkEvent,
  ThreatCategory,
  ThreatIndicator,
} from '../../shared/network-guard'

/** Per-category default decision + confidence when an indicator omits its own. */
const CATEGORY_POLICY: Record<ThreatCategory, { decision: NetworkDecision; confidence: number; reason: string }> = {
  c2: { decision: 'block', confidence: 0.97, reason: 'known_c2' },
  botnet: { decision: 'block', confidence: 0.95, reason: 'botnet_infrastructure' },
  malware_distribution: { decision: 'block', confidence: 0.95, reason: 'malware_distribution' },
  cryptomining: { decision: 'block', confidence: 0.9, reason: 'cryptomining_pool' },
  phishing: { decision: 'block', confidence: 0.9, reason: 'phishing' },
  residential_proxy: { decision: 'alert', confidence: 0.8, reason: 'residential_proxy' },
  tor_exit: { decision: 'alert', confidence: 0.6, reason: 'tor_exit_node' },
  newly_registered: { decision: 'alert', confidence: 0.5, reason: 'newly_registered_domain' },
  spam: { decision: 'alert', confidence: 0.6, reason: 'spam_source' },
}

export function categoryDecision(category: ThreatCategory): NetworkDecision {
  return CATEGORY_POLICY[category].decision
}

/** Lowercase, strip a trailing dot and any port suffix. */
export function normalizeDomain(host: string): string {
  let h = host.trim().toLowerCase()
  // Strip a :port suffix only for hostnames (never for bare IPv6).
  if (!h.includes('::') && /:\d+$/.test(h)) h = h.replace(/:\d+$/, '')
  if (h.endsWith('.')) h = h.slice(0, -1)
  return h
}

export function isIpAddress(value: string): boolean {
  return ipv4ToNumber(value) !== null || ipv6ToBigInt(value) !== null
}

interface IndicatorIndex {
  domains: Map<string, ThreatIndicator>
  ips: Map<string, ThreatIndicator>
  cidrs: { parsed: ReturnType<typeof parseCidr>; indicator: ThreatIndicator }[]
}

/** Build fast lookup structures from a flat indicator list. */
export function buildIndicatorIndex(indicators: ThreatIndicator[]): IndicatorIndex {
  const index: IndicatorIndex = { domains: new Map(), ips: new Map(), cidrs: [] }
  for (const ind of indicators) {
    if (ind.type === 'domain') {
      index.domains.set(normalizeDomain(ind.value), ind)
    } else if (ind.type === 'ip') {
      index.ips.set(ind.value.trim().toLowerCase(), ind)
    } else if (ind.type === 'cidr') {
      const parsed = parseCidr(ind.value)
      if (parsed) index.cidrs.push({ parsed, indicator: ind })
    }
  }
  return index
}

/** Enumerate a domain and its parent domains: a.b.c → [a.b.c, b.c, c]. */
function domainAndParents(domain: string): string[] {
  const labels = domain.split('.')
  const out: string[] = []
  for (let i = 0; i < labels.length - 1; i++) {
    out.push(labels.slice(i).join('.'))
  }
  if (labels.length === 1) out.push(domain)
  return out
}

/** Return the highest-priority indicator match for a destination, or null. */
export function matchDestination(destination: string, index: IndicatorIndex): IndicatorMatch | null {
  if (isIpAddress(destination)) {
    const ip = destination.trim().toLowerCase()
    const ipHit = index.ips.get(ip)
    if (ipHit) return { indicator: ipHit, via: 'ip', matchedValue: ip }
    for (const { parsed, indicator } of index.cidrs) {
      if (parsed && ipMatchesCidr(destination, parsed)) {
        return { indicator, via: 'cidr', matchedValue: parsed.raw }
      }
    }
    return null
  }

  const domain = normalizeDomain(destination)
  const exact = index.domains.get(domain)
  if (exact) return { indicator: exact, via: 'domain', matchedValue: domain }
  // Parent-domain match: sub.evil.com is covered by an evil.com indicator.
  const parents = domainAndParents(domain)
  for (let i = 1; i < parents.length; i++) {
    const hit = index.domains.get(parents[i])
    if (hit) return { indicator: hit, via: 'parent-domain', matchedValue: parents[i] }
  }
  return null
}

/** Decision + confidence + reason for a match (indicator confidence wins). */
export function decide(match: IndicatorMatch): { decision: NetworkDecision; confidence: number; reason: string; category: ThreatCategory } {
  const policy = CATEGORY_POLICY[match.indicator.category]
  const confidence = typeof match.indicator.confidence === 'number'
    ? Math.max(0, Math.min(1, match.indicator.confidence))
    : policy.confidence
  return { decision: policy.decision, confidence, reason: policy.reason, category: match.indicator.category }
}

/** Full pipeline: evaluate a destination into a structured NetworkEvent. */
export function evaluateDestination(
  input: DestinationInput,
  index: IndicatorIndex,
  now: number = Date.now(),
): NetworkEvent {
  const timestamp = new Date(now).toISOString()
  const destinationType: 'domain' | 'ip' = isIpAddress(input.destination) ? 'ip' : 'domain'
  const match = matchDestination(input.destination, index)

  if (!match) {
    return {
      destination: input.destination,
      destinationType,
      port: input.port,
      protocol: input.protocol,
      decision: 'allow',
      reason: 'no_match',
      confidence: 0,
      timestamp,
    }
  }

  const { decision, confidence, reason, category } = decide(match)
  return {
    destination: input.destination,
    destinationType,
    port: input.port,
    protocol: input.protocol,
    decision,
    reason,
    category,
    confidence,
    matchedIndicator: match.matchedValue,
    timestamp,
  }
}

/** True if any event is a block — used to raise the app-risk network signal. */
export function hasBlockingEvent(events: NetworkEvent[]): boolean {
  return events.some((e) => e.decision === 'block')
}

const VALID_CATEGORIES = new Set<ThreatCategory>(Object.keys(CATEGORY_POLICY) as ThreatCategory[])
const VALID_TYPES = new Set(['domain', 'ip', 'cidr'])
const MAX_INDICATORS = 200_000

/**
 * Coerce untrusted input (a pasted/loaded feed) into a clean ThreatIndicator[].
 * Drops malformed entries rather than throwing, so a partly-bad feed still works.
 */
export function sanitizeIndicators(raw: unknown): ThreatIndicator[] {
  if (!Array.isArray(raw)) return []
  const out: ThreatIndicator[] = []
  for (const item of raw) {
    if (out.length >= MAX_INDICATORS) break
    if (!item || typeof item !== 'object') continue
    const o = item as Record<string, unknown>
    const value = typeof o.value === 'string' ? o.value.trim() : ''
    const kind = o.type
    const category = o.category
    if (!value || value.length > 500) continue
    if (typeof kind !== 'string' || !VALID_TYPES.has(kind)) continue
    if (typeof category !== 'string' || !VALID_CATEGORIES.has(category as ThreatCategory)) continue
    const indicator: ThreatIndicator = {
      value,
      type: kind as ThreatIndicator['type'],
      category: category as ThreatCategory,
    }
    if (typeof o.source === 'string' && o.source.length <= 200) indicator.source = o.source
    if (typeof o.confidence === 'number' && o.confidence >= 0 && o.confidence <= 1) {
      indicator.confidence = o.confidence
    }
    out.push(indicator)
  }
  return out
}
