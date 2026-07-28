/**
 * Thin OSV.dev query client for optional enrichment of vulnerability scans.
 * Soft-fails on network errors; injectable fetch for tests. Not a full NVD dump.
 */

import type { InstalledApp } from '../platform/types'
import type { InventoryFinding } from './desktop-inventory'

const DEFAULT_OSV_URL = 'https://api.osv.dev/v1/query'
const DEFAULT_TIMEOUT_MS = 4_000
const MAX_QUERIES = 8
const MAX_VULNS_PER_PKG = 5

export interface OsvQueryPackage {
  name: string
  ecosystem: string
  version: string
}

export interface OsvVuln {
  id: string
  summary?: string
}

export interface OsvClientDeps {
  fetchFn?: typeof fetch
  endpoint?: string
  timeoutMs?: number
}

/** Map common inventory names → OSV ecosystem package queries. */
export function guessOsvPackages(app: InstalledApp): OsvQueryPackage[] {
  const name = (app.name || '').trim().toLowerCase()
  const version = (app.version || '').trim()
  if (!name || !version || version === 'unknown') return []

  const out: OsvQueryPackage[] = []
  const push = (pkg: string, ecosystem: string): void => {
    out.push({ name: pkg, ecosystem, version })
  }

  if (/^(openssl|libssl)/.test(name)) push('openssl', 'Debian')
  else if (/^(curl|libcurl)/.test(name)) push('curl', 'Debian')
  else if (/^openssh/.test(name)) push('openssh', 'Debian')
  else if (/^(xz-utils|liblzma)/.test(name)) push('xz-utils', 'Debian')
  else if (/^sudo$/.test(name)) push('sudo', 'Debian')
  else if (/^(polkit|policykit)/.test(name)) push('policykit-1', 'Debian')
  else if (/log4j/.test(name)) push('org.apache.logging.log4j:log4j-core', 'Maven')
  else if (/^nodejs$|^node\.js$/.test(name)) push('nodejs', 'Debian')
  else return []

  return out
}

export async function queryOsv(
  pkg: OsvQueryPackage,
  deps: OsvClientDeps = {},
): Promise<OsvVuln[]> {
  const fetchFn = deps.fetchFn ?? fetch
  const endpoint = deps.endpoint ?? DEFAULT_OSV_URL
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetchFn(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        version: pkg.version,
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
      }),
      signal: controller.signal,
    })
    if (!res.ok) return []
    const json = (await res.json()) as { vulns?: Array<{ id?: string; summary?: string }> }
    const vulns = Array.isArray(json.vulns) ? json.vulns : []
    return vulns
      .filter((v) => typeof v.id === 'string' && v.id.startsWith('CVE-'))
      .slice(0, MAX_VULNS_PER_PKG)
      .map((v) => ({ id: v.id as string, summary: v.summary }))
  } catch {
    return []
  } finally {
    clearTimeout(timer)
  }
}

export async function scanAppsWithOsv(
  apps: InstalledApp[],
  deps: OsvClientDeps = {},
): Promise<InventoryFinding[]> {
  const findings: InventoryFinding[] = []
  const seen = new Set<string>()
  let queries = 0

  for (const app of apps) {
    for (const pkg of guessOsvPackages(app)) {
      if (queries >= MAX_QUERIES) return findings
      queries++
      const vulns = await queryOsv(pkg, deps)
      for (const v of vulns) {
        const key = `${v.id}|${app.name}`
        if (seen.has(key)) continue
        seen.add(key)
        findings.push({
          level: 'likely_affected',
          subjectName: v.id,
          reason: `osv_match:${pkg.ecosystem}:${pkg.name}@${pkg.version}`.slice(0, 200),
          category: 'osv',
        })
      }
    }
  }
  return findings
}
