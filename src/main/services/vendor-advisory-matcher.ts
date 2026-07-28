/**
 * Offline vendor/distro advisory matcher for RUN_VULNERABILITY_SCAN.
 * Catalog: rules/security/vendor-advisories.json
 * Version decisions go through evaluateAdvisoryVersion (shared with future feed adapters).
 */

import { readFileSync, statSync } from 'fs'
import path from 'path'
import type { InstalledApp } from '../platform/types'
import type { InventoryFinding } from './desktop-inventory'
import { matchesKevAlias } from './kev-matcher'
import { evaluateAdvisoryVersion, type AdvisoryVersionRange } from './vendor-advisories'

export type AdvisorySeverity = 'critical' | 'high' | 'medium' | 'low'

export interface VendorAdvisoryEntry {
  id: string
  cveId: string
  vendor: string
  product: string
  aliases: string[]
  severity: AdvisorySeverity
  ecosystem?: string
  introduced?: string
  fixedIn?: string
  vulnerableBelow?: string
  requiredAction?: string
  reference?: string
}

export interface VendorAdvisoryCatalog {
  version: string
  updatedAt: string
  source?: string
  description?: string
  entries: VendorAdvisoryEntry[]
}

export interface AdvisoryHit {
  id: string
  cveId: string
  appName: string
  installedVersion: string
  product: string
  vendor: string
  severity: AdvisorySeverity
  reason: string
  requiredAction?: string
  range: AdvisoryVersionRange
  reference?: string
}

let cached: { catalogPath: string; mtimeMs: number; catalog: VendorAdvisoryCatalog } | null = null

function defaultCatalogPath(): string {
  return path.resolve(__dirname, '../../../rules/security/vendor-advisories.json')
}

export function resetVendorAdvisoryCatalogCache(): void {
  cached = null
}

export function loadVendorAdvisoryCatalog(
  catalogPath: string = defaultCatalogPath(),
): VendorAdvisoryCatalog {
  const raw = readFileSync(catalogPath, 'utf-8')
  const catalog = JSON.parse(raw) as VendorAdvisoryCatalog
  if (!Array.isArray(catalog.entries)) throw new Error('vendor-advisories catalog missing entries[]')
  return catalog
}

function getCatalog(catalogPath?: string): VendorAdvisoryCatalog {
  const p = catalogPath ?? defaultCatalogPath()
  try {
    const { mtimeMs } = statSync(p)
    if (cached && cached.catalogPath === p && cached.mtimeMs === mtimeMs) return cached.catalog
    const catalog = loadVendorAdvisoryCatalog(p)
    cached = { catalogPath: p, mtimeMs, catalog }
    return catalog
  } catch {
    return cached?.catalog ?? { version: '0', updatedAt: '', entries: [] }
  }
}

export function getVendorAdvisoryCatalogInfo(
  catalogPath?: string,
  catalog?: VendorAdvisoryCatalog,
): { version: string; entryCount: number } {
  const c = catalog ?? loadVendorAdvisoryCatalog(catalogPath ?? defaultCatalogPath())
  return { version: c.version, entryCount: c.entries.length }
}

function entryRange(entry: VendorAdvisoryEntry): AdvisoryVersionRange {
  return {
    introduced: entry.introduced,
    fixedIn: entry.fixedIn,
    vulnerableBelow: entry.vulnerableBelow,
  }
}

export function advisoryFixRecommendation(
  hit: Pick<AdvisoryHit, 'appName' | 'requiredAction' | 'range'>,
): string | undefined {
  const action = (hit.requiredAction || '').trim()
  if (action) return action.slice(0, 240)

  const floor = (hit.range.fixedIn || hit.range.vulnerableBelow || '').trim()
  if (!floor) return undefined
  const app = (hit.appName || 'package').trim() || 'package'
  return `Upgrade ${app} to ${floor} or newer`.slice(0, 240)
}

/**
 * Match installed apps against the curated advisory catalog.
 * Only emits hits when evaluateAdvisoryVersion returns `affected`.
 * `unknown` / `fixed` / `not_affected` are silent (prefer no false positives without a range).
 */
export function matchVendorAdvisoriesAgainstApps(
  apps: InstalledApp[],
  opts: {
    catalogPath?: string
    catalog?: VendorAdvisoryCatalog
    maxHits?: number
  } = {},
): AdvisoryHit[] {
  const catalog = opts.catalog ?? getCatalog(opts.catalogPath)
  const maxHits = opts.maxHits ?? 100
  const hits: AdvisoryHit[] = []
  const seen = new Set<string>()

  for (const app of apps) {
    const name = (app.name || '').trim()
    if (!name) continue
    const ver = (app.version || '').trim() || 'unknown'

    for (const entry of catalog.entries) {
      const aliasHit = entry.aliases.some((al) => matchesKevAlias(name, al))
        || matchesKevAlias(name, entry.product)
      if (!aliasHit) continue

      const range = entryRange(entry)
      const status = evaluateAdvisoryVersion(ver, range)
      if (status !== 'affected') continue

      const key = `${entry.id}|${name}|${ver}`
      if (seen.has(key)) continue
      seen.add(key)

      const hasIntroduced = !!range.introduced?.trim()
      const floor = (range.fixedIn || range.vulnerableBelow || '').trim()
      hits.push({
        id: entry.id,
        cveId: entry.cveId,
        appName: name,
        installedVersion: ver,
        product: entry.product,
        vendor: entry.vendor,
        severity: entry.severity,
        reason: floor
          ? (hasIntroduced
            ? `advisory_range_${range.introduced}_to_${floor}`
            : `advisory_version_match_<${floor}`)
          : 'advisory_product_match',
        requiredAction: entry.requiredAction,
        range,
        reference: entry.reference,
      })
      if (hits.length >= maxHits) return hits
    }
  }
  return hits
}

export function advisoryHitsToCloudFindings(hits: AdvisoryHit[]): InventoryFinding[] {
  return hits.map((h) => {
    const fixRecommendation = advisoryFixRecommendation(h)
    const evidence = [
      `advisory:${h.id}`,
      `app:${h.appName}@${h.installedVersion}`,
      ...(h.reference ? [`ref:${h.reference}`] : []),
    ].slice(0, 12)
    return {
      level: h.severity === 'critical' || h.severity === 'high'
        ? 'likely_affected'
        : 'potential_match',
      subjectName: h.cveId,
      reason: `${h.reason}:${h.appName}@${h.installedVersion}`.slice(0, 200),
      category: 'advisory',
      confidence: 0.9,
      evidence,
      ...(fixRecommendation ? { fixRecommendation } : {}),
    }
  })
}
