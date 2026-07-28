/**
 * CISA KEV feed sync + merge with the curated vendored catalog.
 * Live feed expands coverage; vendored entries keep version gates / richer aliases.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, statSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import {
  loadKevCatalog,
  type KevCatalog,
  type KevEntry,
  type KevSeverity,
  resetKevCatalogCache,
} from './kev-matcher'

export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

const FETCH_TIMEOUT_MS = 20_000
const MAX_FEED_BYTES = 8 * 1024 * 1024
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000

/** Standalone aliases that are too generic for inventory matching. */
const GENERIC_TOKENS = new Set([
  'windows', 'linux', 'android', 'macos', 'mac', 'ios', 'apple', 'microsoft',
  'google', 'adobe', 'cisco', 'oracle', 'ibm', 'apache', 'kernel', 'server',
  'client', 'software', 'update', 'multiple', 'various', 'unknown', 'web',
  'browser', 'office', 'system', 'manager', 'service', 'services', 'plugin',
  'framework', 'library', 'tools', 'tool', 'suite', 'platform', 'device',
  'network', 'security', 'remote', 'desktop', 'file', 'data', 'cloud',
])

export interface CisaKevVulnerability {
  cveID?: string
  vendorProject?: string
  product?: string
  vulnerabilityName?: string
  dateAdded?: string
  shortDescription?: string
  requiredAction?: string
  knownRansomwareCampaignUse?: string
}

export interface CisaKevFeed {
  title?: string
  catalogVersion?: string
  dateReleased?: string
  count?: number
  vulnerabilities?: CisaKevVulnerability[]
}

export interface KevFeedDeps {
  fetchFn?: typeof fetch
  cacheDir?: string
  vendoredPath?: string
  url?: string
  nowMs?: number
}

let overrideCacheDir: string | null = null

/** Tests: pin cache directory (avoids Electron userData). */
export function setKevFeedCacheDirForTest(dir: string | null): void {
  overrideCacheDir = dir
}

function resolveCacheDir(deps: KevFeedDeps): string {
  if (deps.cacheDir) return deps.cacheDir
  if (overrideCacheDir) return overrideCacheDir
  try {
    // Lazy electron — agent runs inside Electron; unit tests set override/cacheDir.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { app } = require('electron') as { app: { getPath: (n: string) => string } }
    return join(app.getPath('userData'), 'kev-feed')
  } catch {
    return join(tmpdir(), 'bulwark-kev-feed')
  }
}

function cachePath(dir: string): string {
  return join(dir, 'cisa-kev.json')
}

function buildAliases(vendor: string, product: string): string[] {
  const aliases = new Set<string>()
  const prod = product.trim()
  const vend = vendor.trim()
  const prodNorm = prod.toLowerCase()

  // Avoid bare generic products ("Windows", "Linux") — they flood desktop inventories.
  if (prod && !GENERIC_TOKENS.has(prodNorm)) {
    aliases.add(prodNorm)
  }
  if (prod && vend) {
    const combo = `${vend} ${prod}`.toLowerCase()
    aliases.add(combo)
  }

  for (const token of prodNorm.split(/[^a-z0-9.+-]+/).filter(Boolean)) {
    if (token.length < 4) continue
    if (GENERIC_TOKENS.has(token)) continue
    if (/^\d+$/.test(token)) continue
    aliases.add(token)
  }

  // Keep multi-word product phrases (e.g. "connect secure") when useful
  const words = prodNorm.split(/[^a-z0-9.+-]+/).filter((w) => w.length >= 3)
  if (words.length >= 2) {
    const phrase = words.slice(0, 3).join(' ')
    aliases.add(phrase)
  }

  return [...aliases].filter((a) => a.length >= 2).slice(0, 12)
}

export function cisaVulnToKevEntry(v: CisaKevVulnerability): KevEntry | null {
  const cveId = typeof v.cveID === 'string' ? v.cveID.trim().toUpperCase() : ''
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return null
  const vendor = (v.vendorProject || 'Unknown').trim() || 'Unknown'
  const product = (v.product || '').trim()
  if (!product) return null
  const ransomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known'
  const severity: KevSeverity = ransomware ? 'critical' : 'high'
  const aliases = buildAliases(vendor, product)
  if (aliases.length === 0) {
    // Last resort: vendor+product combo only (never a lone generic token)
    const combo = `${vendor} ${product}`.trim().toLowerCase()
    if (combo.length >= 3) aliases.push(combo)
    else return null
  }
  return {
    cveId,
    vendor,
    product,
    aliases,
    severity,
    ransomware,
    dateAdded: typeof v.dateAdded === 'string' ? v.dateAdded : undefined,
    requiredAction: typeof v.requiredAction === 'string' ? v.requiredAction : undefined,
  }
}

export function cisaFeedToCatalog(feed: CisaKevFeed): KevCatalog {
  const entries: KevEntry[] = []
  const seen = new Set<string>()
  for (const v of feed.vulnerabilities || []) {
    const e = cisaVulnToKevEntry(v)
    if (!e) continue
    if (seen.has(e.cveId)) continue
    seen.add(e.cveId)
    entries.push(e)
  }
  return {
    version: String(feed.catalogVersion || 'cisa'),
    updatedAt: String(feed.dateReleased || new Date().toISOString()),
    source: 'CISA Known Exploited Vulnerabilities catalog',
    description: `Live/cached CISA KEV (${entries.length} entries)`,
    entries,
  }
}

/** Vendored wins on version gates; aliases are unioned; ransomware OR'd. */
export function mergeKevCatalogs(vendored: KevCatalog, live: KevCatalog): KevCatalog {
  const map = new Map<string, KevEntry>()
  for (const e of live.entries) map.set(e.cveId, { ...e, aliases: [...e.aliases] })
  for (const e of vendored.entries) {
    const prev = map.get(e.cveId)
    if (!prev) {
      map.set(e.cveId, { ...e, aliases: [...e.aliases] })
      continue
    }
    map.set(e.cveId, {
      ...prev,
      vendor: e.vendor || prev.vendor,
      product: e.product || prev.product,
      severity: e.severity || prev.severity,
      aliases: [...new Set([...prev.aliases, ...e.aliases])],
      ransomware: Boolean(e.ransomware || prev.ransomware),
      dateAdded: e.dateAdded || prev.dateAdded,
      requiredAction: e.requiredAction || prev.requiredAction,
      vulnerableBelow: e.vulnerableBelow || prev.vulnerableBelow,
    })
  }
  return {
    version: live.version && live.version !== '0' ? live.version : vendored.version,
    updatedAt: live.updatedAt || vendored.updatedAt,
    source: `merged:vendored+${live.source || 'cisa'}`,
    description: `Merged KEV (${map.size} CVEs)`,
    entries: [...map.values()],
  }
}

function readCachedCatalog(dir: string): KevCatalog | null {
  const p = cachePath(dir)
  if (!existsSync(p)) return null
  try {
    const raw = JSON.parse(readFileSync(p, 'utf-8')) as CisaKevFeed
    return cisaFeedToCatalog(raw)
  } catch {
    return null
  }
}

function cacheIsFresh(dir: string, nowMs: number): boolean {
  const p = cachePath(dir)
  if (!existsSync(p)) return false
  try {
    return nowMs - statSync(p).mtimeMs < CACHE_MAX_AGE_MS
  } catch {
    return false
  }
}

export async function fetchCisaKevFeed(deps: KevFeedDeps = {}): Promise<CisaKevFeed> {
  const fetchFn = deps.fetchFn ?? fetch
  const url = deps.url ?? CISA_KEV_URL
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await fetchFn(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const text = await res.text()
    if (text.length > MAX_FEED_BYTES) throw new Error('KEV feed too large')
    const json = JSON.parse(text) as CisaKevFeed
    if (!Array.isArray(json.vulnerabilities)) throw new Error('invalid KEV feed shape')
    return json
  } finally {
    clearTimeout(timer)
  }
}

function writeCache(dir: string, feed: CisaKevFeed): void {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const p = cachePath(dir)
  const tmp = `${p}.tmp`
  writeFileSync(tmp, JSON.stringify(feed), 'utf-8')
  renameSync(tmp, p)
}

export interface EffectiveKevResult {
  catalog: KevCatalog
  source: 'vendored' | 'cache' | 'live' | 'merged-cache' | 'merged-live'
  synced: boolean
  error?: string
}

/**
 * Build the effective KEV catalog for matching.
 * - Always starts from vendored curated entries (version gates).
 * - Uses on-disk CISA cache when present.
 * - When `sync` is true (or cache stale/missing and sync !== false with syncIfStale), refreshes from CISA.
 */
export async function getEffectiveKevCatalog(
  opts: { sync?: boolean; syncIfStale?: boolean } = {},
  deps: KevFeedDeps = {},
): Promise<EffectiveKevResult> {
  const vendored = loadKevCatalog(deps.vendoredPath)
  const dir = resolveCacheDir(deps)
  const now = deps.nowMs ?? Date.now()
  const cached = readCachedCatalog(dir)
  const wantSync =
    opts.sync === true
    || (opts.syncIfStale === true && !cacheIsFresh(dir, now))

  if (wantSync) {
    try {
      const feed = await fetchCisaKevFeed(deps)
      writeCache(dir, feed)
      resetKevCatalogCache()
      const live = cisaFeedToCatalog(feed)
      return {
        catalog: mergeKevCatalogs(vendored, live),
        source: 'merged-live',
        synced: true,
      }
    } catch (err) {
      if (cached) {
        return {
          catalog: mergeKevCatalogs(vendored, cached),
          source: 'merged-cache',
          synced: false,
          error: err instanceof Error ? err.message : String(err),
        }
      }
      return {
        catalog: vendored,
        source: 'vendored',
        synced: false,
        error: err instanceof Error ? err.message : String(err),
      }
    }
  }

  if (cached) {
    return {
      catalog: mergeKevCatalogs(vendored, cached),
      source: 'merged-cache',
      synced: false,
    }
  }
  return { catalog: vendored, source: 'vendored', synced: false }
}
