// Portmaster-style network monitoring types: a live per-application view of
// connections (each evaluated by Network Guard) and an on-device TCP port
// scanner. Local-first — connection metadata only, never payloads.

import type { NetworkDecision, ThreatCategory } from './network-guard'

/** An open port found by the scanner. */
export interface OpenPort {
  port: number
  /** Best-guess service name for the port (e.g. 'https'), or 'unknown'. */
  service: string
}

export interface PortScanResult {
  host: string
  openPorts: OpenPort[]
  /** How many ports were probed. */
  scanned: number
  durationMs: number
  /** Set when the request was rejected/failed (e.g. invalid port spec). */
  error?: string
}

/** A single connection, enriched with the owning app and a guard verdict. */
export interface ConnectionRecord {
  remoteAddress: string
  remotePort: number
  localPort: number
  pid: number | null
  /** Process/app name (best effort), or 'unknown'. */
  process: string
  decision: NetworkDecision
  reason: string
  category?: ThreatCategory
  confidence: number
  /** ISO 2-letter country code of the remote (via GeoIP), if known. */
  country?: string
}

/** Connections grouped by owning application (the Portmaster view). */
export interface AppConnections {
  app: string
  pid: number | null
  count: number
  /** Worst decision across this app's connections. */
  worst: NetworkDecision
  connections: ConnectionRecord[]
}

export interface ConnectionOverview {
  apps: AppConnections[]
  totalConnections: number
  blocked: number
  alerted: number
  listeningPorts: number[]
  generatedAt: string
}
