// Filter-list catalog + download/cache/parse/merge for the Secure DNS resolver.
// Local-first: lists are cached to userData so the resolver works offline after
// a first sync, and nothing is fetched unless the user enables a list.

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, statSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import { parseHostsList } from './dns-filter'
import type { FilterListInfo, FilterListStatus, FilterListsState } from '../../shared/filter-lists'

const MAX_LIST_BYTES = 30 * 1024 * 1024 // 30 MB per list
const FETCH_TIMEOUT_MS = 30_000

/** Curated, well-known filter lists. URLs are the lists' canonical raw sources. */
export const FILTER_LIST_CATALOG: FilterListInfo[] = [
  {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    description: 'Malware distribution hosts from abuse.ch — small, high-signal.',
    category: 'malware',
    url: 'https://urlhaus.abuse.ch/downloads/hostfile/',
    enabledByDefault: true,
  },
  {
    id: 'stevenblack',
    name: 'StevenBlack Unified',
    description: 'Widely-used unified ads + malware hosts list.',
    category: 'ads+malware',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    enabledByDefault: false,
  },
  {
    id: 'hagezi-light',
    name: 'HaGeZi Light',
    description: 'Lightweight ads/tracking blocklist for minimal breakage.',
    category: 'ads+tracking',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt',
    enabledByDefault: false,
  },
]

function catalogById(id: string): FilterListInfo | undefined {
  return FILTER_LIST_CATALOG.find((l) => l.id === id)
}

function listsDir(): string {
  const dir = join(app.getPath('userData'), 'filter-lists')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function cachePath(id: string): string {
  return join(listsDir(), `${id}.txt`)
}

/** Download a filter list with size + timeout caps. */
export async function fetchFilterList(url: string): Promise<string> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { Accept: 'text/plain' } })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const len = res.headers.get('content-length')
    if (len && parseInt(len, 10) > MAX_LIST_BYTES) throw new Error('list too large')
    const text = await res.text()
    if (text.length > MAX_LIST_BYTES) throw new Error('list too large')
    return text
  } finally {
    clearTimeout(timeout)
  }
}

function readCachedDomains(id: string): string[] {
  const p = cachePath(id)
  if (!existsSync(p)) return []
  try {
    return parseHostsList(readFileSync(p, 'utf-8'))
  } catch {
    return []
  }
}

function cachedUpdatedAt(id: string): string | null {
  const p = cachePath(id)
  if (!existsSync(p)) return null
  try {
    return new Date(statSync(p).mtimeMs).toISOString()
  } catch {
    return null
  }
}

/** Build state (no network) from the catalog, enabled ids, and cache on disk. */
export function getFilterListsState(enabledIds: string[]): FilterListsState {
  const enabled = new Set(enabledIds)
  const merged = new Set<string>()
  const lists: FilterListStatus[] = FILTER_LIST_CATALOG.map((info) => {
    const domains = readCachedDomains(info.id)
    const isEnabled = enabled.has(info.id)
    if (isEnabled) for (const d of domains) merged.add(d)
    return {
      id: info.id,
      name: info.name,
      description: info.description,
      category: info.category,
      enabled: isEnabled,
      domainCount: domains.length,
      cached: domains.length > 0,
      updatedAt: cachedUpdatedAt(info.id),
    }
  })
  return { lists, totalDomains: merged.size }
}

/** Download + cache each enabled list, then return refreshed state. */
export async function syncFilterLists(enabledIds: string[]): Promise<FilterListsState> {
  const errors = new Map<string, string>()
  for (const id of enabledIds) {
    const info = catalogById(id)
    if (!info) continue
    try {
      const text = await fetchFilterList(info.url)
      const tmp = cachePath(id) + '.tmp'
      writeFileSync(tmp, text, 'utf-8')
      renameSync(tmp, cachePath(id))
    } catch (err) {
      errors.set(id, err instanceof Error ? err.message : 'download failed')
    }
  }
  const state = getFilterListsState(enabledIds)
  if (errors.size > 0) {
    for (const l of state.lists) {
      const e = errors.get(l.id)
      if (e) l.lastError = e
    }
  }
  return state
}

/** Merge all enabled+cached list domains into a single de-duplicated array. */
export function mergedBlocklistDomains(enabledIds: string[]): string[] {
  const merged = new Set<string>()
  for (const id of enabledIds) {
    if (!catalogById(id)) continue
    for (const d of readCachedDomains(id)) merged.add(d)
  }
  return [...merged]
}
