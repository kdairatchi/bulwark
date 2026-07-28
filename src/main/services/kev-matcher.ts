/**
 * Offline CISA KEV name/version matcher for basic CVE findings.
 * Catalog: rules/security/kev.json — curated subset, not full NVD/OSV.
 */

import { readFileSync, statSync } from 'fs'
import path from 'path'
import type { InstalledApp } from '../platform/types'
import type { InventoryFinding } from './desktop-inventory'
import { isVersionAtLeast } from './cve-filter'

export type KevSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface KevEntry {
  cveId: string
  vendor: string
  product: string
  aliases: string[]
  severity: KevSeverity
  ransomware?: boolean
  dateAdded?: string
  requiredAction?: string
  vulnerableBelow?: string
}

export interface KevCatalog {
  version: string
  updatedAt: string
  source?: string
  description?: string
  entries: KevEntry[]
}

export interface KevHit {
  cveId: string
  appName: string
  installedVersion: string
  product: string
  vendor: string
  severity: KevSeverity
  ransomware: boolean
  reason: string
  requiredAction?: string
}

let cached: { catalogPath: string; mtimeMs: number; catalog: KevCatalog } | null = null

function defaultCatalogPath(): string {
  return path.resolve(__dirname, '../../../rules/security/kev.json')
}

export function resetKevCatalogCache(): void {
  cached = null
}

export function loadKevCatalog(catalogPath: string = defaultCatalogPath()): KevCatalog {
  const raw = readFileSync(catalogPath, 'utf-8')
  const catalog = JSON.parse(raw) as KevCatalog
  if (!Array.isArray(catalog.entries)) throw new Error('kev catalog missing entries[]')
  return catalog
}

function getCatalog(catalogPath?: string): KevCatalog {
  const p = catalogPath ?? defaultCatalogPath()
  try {
    const { mtimeMs } = statSync(p)
    if (cached && cached.catalogPath === p && cached.mtimeMs === mtimeMs) return cached.catalog
    const catalog = loadKevCatalog(p)
    cached = { catalogPath: p, mtimeMs, catalog }
    return catalog
  } catch {
    return cached?.catalog ?? { version: '0', updatedAt: '', entries: [] }
  }
}

export function getKevCatalogInfo(catalogPath?: string, catalog?: KevCatalog): { version: string; entryCount: number } {
  const c = catalog ?? loadKevCatalog(catalogPath ?? defaultCatalogPath())
  return { version: c.version, entryCount: c.entries.length }
}

/** Normalize product/app names for matching. */
export function normalizeProductName(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/[^a-z0-9.+-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * Prefer silence: require token / package-style match, not loose substring.
 * "chrome" matches "Google Chrome"; "libssl" matches "libssl3"; "curl" ≠ "curling".
 */
export function matchesKevAlias(appName: string, alias: string): boolean {
  const n = normalizeProductName(appName)
  const a = normalizeProductName(alias)
  if (!n || !a || a.length < 2) return false
  if (n === a) return true

  const tokens = n.split(' ').filter(Boolean)
  if (tokens.includes(a)) return true

  // Multi-word alias must appear contiguously
  if (a.includes(' ')) {
    return (` ${n} `).includes(` ${a} `)
  }

  // Package-style: alias + version/epoch suffix (libssl → libssl3 / libssl1.1)
  if (a.length >= 4) {
    for (const t of tokens) {
      if (t === a) return true
      if (t.startsWith(a) && t.length > a.length) {
        const rest = t.slice(a.length)
        if (/^[0-9._+-]/.test(rest)) return true
      }
    }
  }

  // Short aliases (2–3 chars): exact token only (already handled)
  return false
}

function versionStillVulnerable(installed: string, vulnerableBelow?: string): boolean {
  if (!vulnerableBelow || !installed || installed === 'unknown' || installed === '0') {
    // No reliable version constraint — treat as potential (caller sets level)
    return true
  }
  try {
    // Flag when installed is NOT yet at/above the fix floor
    return !isVersionAtLeast(installed, vulnerableBelow)
  } catch {
    return true
  }
}

export function matchKevAgainstApps(
  apps: InstalledApp[],
  opts: { catalogPath?: string; catalog?: KevCatalog; maxHits?: number } = {},
): KevHit[] {
  const catalog = opts.catalog ?? getCatalog(opts.catalogPath)
  const maxHits = opts.maxHits ?? 100
  const hits: KevHit[] = []
  const seen = new Set<string>()

  for (const app of apps) {
    const name = (app.name || '').trim()
    if (!name) continue
    const ver = (app.version || '').trim() || 'unknown'

    for (const entry of catalog.entries) {
      const aliasHit = entry.aliases.some((al) => matchesKevAlias(name, al))
        || matchesKevAlias(name, entry.product)
      if (!aliasHit) continue

      const hasVersionGate = !!entry.vulnerableBelow
      if (hasVersionGate && !versionStillVulnerable(ver, entry.vulnerableBelow)) continue

      const key = `${entry.cveId}|${name}|${ver}`
      if (seen.has(key)) continue
      seen.add(key)

      hits.push({
        cveId: entry.cveId,
        appName: name,
        installedVersion: ver,
        product: entry.product,
        vendor: entry.vendor,
        severity: entry.severity,
        ransomware: entry.ransomware === true,
        reason: hasVersionGate
          ? `kev_version_match_<${entry.vulnerableBelow}`
          : 'kev_product_match',
        requiredAction: entry.requiredAction,
      })
      if (hits.length >= maxHits) return hits
    }
  }
  return hits
}

export function kevHitsToCloudFindings(hits: KevHit[]): InventoryFinding[] {
  return hits.map((h) => ({
    level: h.severity === 'critical' || h.severity === 'high'
      ? (h.reason.startsWith('kev_version_match') ? 'likely_affected' : 'potential_match')
      : 'potential_match',
    subjectName: h.cveId,
    reason: `${h.reason}:${h.appName}@${h.installedVersion}${h.ransomware ? ':ransomware' : ''}`.slice(0, 200),
    category: 'kev',
  }))
}
