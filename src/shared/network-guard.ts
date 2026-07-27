// Network Guard: categorized threat-indicator matching + a transparent
// allow/alert/block decision for a network destination. Local-first — it
// inspects destination metadata (domain/IP) only, never packet payloads
// (see docs/privacy/README.md). The decision path is deterministic; the same
// destination + indicator set always yields the same NetworkEvent.

/**
 * Threat categories, from the product spec's Threat Monitoring detection set.
 * The FBI has specifically highlighted streaming devices being turned into
 * residential proxy nodes, which is why `residential_proxy` is first-class.
 */
export type ThreatCategory =
  | 'c2'
  | 'botnet'
  | 'malware_distribution'
  | 'cryptomining'
  | 'phishing'
  | 'residential_proxy'
  | 'tor_exit'
  | 'newly_registered'
  | 'spam'

export type IndicatorType = 'domain' | 'ip' | 'cidr'

/** A single threat indicator from a feed (URLhaus, ThreatFox, abuse.ch, …). */
export interface ThreatIndicator {
  value: string
  type: IndicatorType
  category: ThreatCategory
  /** Feed/source name for attribution (licensing checked per feed). */
  source?: string
  /** Optional per-indicator confidence (0–1); overrides the category default. */
  confidence?: number
}

/** What to do with a destination. */
export type NetworkDecision = 'allow' | 'alert' | 'block'

/** The metadata we evaluate — never payloads. */
export interface DestinationInput {
  destination: string
  port?: number
  protocol?: 'tcp' | 'udp'
}

/** Result of matching a destination against the indicator set. */
export interface IndicatorMatch {
  indicator: ThreatIndicator
  /** How the match was made. */
  via: 'domain' | 'parent-domain' | 'ip' | 'cidr'
  /** The specific indicator value that matched. */
  matchedValue: string
}

/**
 * Structured, metadata-only event (matches the spec's upload shape). This is
 * what would be stored/uploaded — no content, no payloads.
 */
export interface NetworkEvent {
  destination: string
  destinationType: 'domain' | 'ip'
  port?: number
  protocol?: 'tcp' | 'udp'
  decision: NetworkDecision
  /** Machine-readable reason, e.g. 'known_c2', 'no_match'. */
  reason: string
  category?: ThreatCategory
  /** Confidence in the threat (0–1). 0 when allowed. */
  confidence: number
  matchedIndicator?: string
  timestamp: string
}
