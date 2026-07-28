/**
 * FIRST.org EPSS enrichment for CVE findings (soft-fail, bounded).
 */

import type { InventoryFinding } from './desktop-inventory'

const DEFAULT_EPSS_URL = 'https://api.first.org/data/v1/epss'
const DEFAULT_TIMEOUT_MS = 6_000
const MAX_CVES = 40

export interface EpssScore {
  cve: string
  epss: number
  percentile: number
}

export interface EpssClientDeps {
  fetchFn?: typeof fetch
  endpoint?: string
  timeoutMs?: number
}

export async function fetchEpssScores(
  cveIds: string[],
  deps: EpssClientDeps = {},
): Promise<Map<string, EpssScore>> {
  const out = new Map<string, EpssScore>()
  const ids = [...new Set(
    cveIds
      .map((id) => id.trim().toUpperCase())
      .filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)),
  )].slice(0, MAX_CVES)
  if (ids.length === 0) return out

  const fetchFn = deps.fetchFn ?? fetch
  const endpoint = deps.endpoint ?? DEFAULT_EPSS_URL
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const qs = ids.map((id) => `cve=${encodeURIComponent(id)}`).join('&')
    const res = await fetchFn(`${endpoint}?${qs}`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    })
    if (!res.ok) return out
    const json = (await res.json()) as {
      data?: Array<{ cve?: string; epss?: string; percentile?: string }>
    }
    for (const row of json.data || []) {
      if (typeof row.cve !== 'string') continue
      const epss = Number(row.epss)
      const percentile = Number(row.percentile)
      if (!Number.isFinite(epss) || !Number.isFinite(percentile)) continue
      out.set(row.cve.toUpperCase(), { cve: row.cve.toUpperCase(), epss, percentile })
    }
  } catch {
    /* soft-fail */
  } finally {
    clearTimeout(timer)
  }
  return out
}

/** Append epss=…:pct=… onto CVE/KEV/OSV finding reasons when scores exist. */
export function enrichFindingsWithEpss(
  findings: InventoryFinding[],
  scores: Map<string, EpssScore>,
): InventoryFinding[] {
  if (scores.size === 0) return findings
  return findings.map((f) => {
    if (f.category !== 'kev' && f.category !== 'osv' && f.category !== 'cve') return f
    const score = scores.get(f.subjectName.toUpperCase())
    if (!score) return f
    const tag = `epss=${score.epss.toFixed(4)}:pct=${score.percentile.toFixed(4)}`
    if (f.reason.includes('epss=')) return f
    return {
      ...f,
      reason: `${f.reason}:${tag}`.slice(0, 200),
      // High EPSS (≥0.5) elevates potential → likely when still a CVE hit
      ...(score.epss >= 0.5 && (f.level === 'potential_match' || f.status === 'potential_match' || f.level === 'medium' || f.level === 'low')
        ? {
            level: f.level === 'potential_match' || f.level === 'medium' || f.level === 'low' ? 'high' : f.level,
            status: 'likely_affected' as const,
          }
        : {}),
    }
  })
}
