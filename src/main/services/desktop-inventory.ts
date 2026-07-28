/**
 * Desktop inventory collection + lightweight posture findings for the device API.
 * Pure-ish helpers (platform I/O injected) so unit tests stay offline.
 */

import type { InstalledApp } from '../platform/types'

export interface InventoryFinding {
  level: string
  subjectName: string
  reason: string
  category?: string
  /** Human-readable remediation hint (KEV requiredAction / upgrade floor). */
  fixRecommendation?: string
}

export interface DesktopInventoryPayload {
  apps: Array<{
    name: string
    version: string
    publisher: string
    installDate: string
    sizeKb: number
  }>
  count: number
  platform: string
  hostname: string
  findings: InventoryFinding[]
}

const SUSPICIOUS_NAME_RE = /\b(crack|keygen|cheat|hacktool|miner|coin.?miner|adware)\b/i

/** Deterministic findings from an installed-app list (no ML). */
export function analyzeInstalledApps(apps: InstalledApp[]): InventoryFinding[] {
  const findings: InventoryFinding[] = []
  for (const app of apps) {
    const publisher = (app.publisher || '').trim()
    if (!publisher || /^unknown$/i.test(publisher) || publisher === '-') {
      findings.push({
        level: 'potential_match',
        subjectName: app.name || 'unknown',
        reason: 'unknown_publisher',
        category: 'publisher',
      })
    }
    if (SUSPICIOUS_NAME_RE.test(app.name || '')) {
      findings.push({
        level: 'likely_affected',
        subjectName: app.name,
        reason: 'suspicious_app_name',
        category: 'name',
      })
    }
  }
  // Cap for control-plane reference store memory.
  return findings.slice(0, 200)
}

export function buildInventoryPayload(opts: {
  apps: InstalledApp[]
  platform: string
  hostname: string
}): DesktopInventoryPayload {
  const apps = opts.apps.map((a) => ({
    name: a.name,
    version: a.version,
    publisher: a.publisher,
    installDate: a.installDate,
    sizeKb: a.sizeKb,
  }))
  return {
    apps,
    count: apps.length,
    platform: opts.platform,
    hostname: opts.hostname,
    findings: analyzeInstalledApps(opts.apps),
  }
}

export type InstalledAppsLoader = () => Promise<InstalledApp[]>

/** Collect inventory from the platform (or injected loader for tests). */
export async function collectDesktopInventory(opts: {
  loadApps: InstalledAppsLoader
  platform: string
  hostname: string
}): Promise<DesktopInventoryPayload> {
  const apps = await opts.loadApps()
  return buildInventoryPayload({
    apps,
    platform: opts.platform,
    hostname: opts.hostname,
  })
}
