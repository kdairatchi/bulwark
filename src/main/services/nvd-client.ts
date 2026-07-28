/**
 * Bounded NVD 2.0 CPE matcher for installed applications.
 *
 * NVD is queried only for known product mappings and with isVulnerable=true.
 * This keeps matching conservative and avoids treating a loose display-name
 * match as a vulnerability. The caller must opt in because NVD rate limits
 * vary and an API key is recommended for repeated scans.
 */

import type { InstalledApp } from '../platform/types'
import type { InventoryFinding } from './desktop-inventory'

export const DEFAULT_NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const DEFAULT_TIMEOUT_MS = 8_000
const MAX_QUERIES = 8
const MAX_VULNS_PER_CPE = 10

export interface NvdCpe {
  vendor: string
  product: string
  version: string
  part?: 'a' | 'o' | 'h'
}

export interface NvdClientDeps {
  fetchFn?: typeof fetch
  endpoint?: string
  apiKey?: string
  timeoutMs?: number
}

export interface NvdVulnerability {
  id: string
  description?: string
  severity?: string
  score?: number
  published?: string
  lastModified?: string
}

const PRODUCT_MAP: Array<{ pattern: RegExp; vendor: string; product: string }> = [
  { pattern: /^(curl|libcurl)\b/i, vendor: 'haxx', product: 'curl' },
  { pattern: /^(openssl|libssl)\b/i, vendor: 'openssl', product: 'openssl' },
  { pattern: /^openssh\b/i, vendor: 'openbsd', product: 'openssh' },
  { pattern: /^nginx\b/i, vendor: 'nginx', product: 'nginx' },
  { pattern: /^(apache\s+httpd|httpd)\b/i, vendor: 'apache', product: 'http_server' },
  { pattern: /^(node(?:\.js|js))\b/i, vendor: 'nodejs', product: 'node.js' },
  { pattern: /log4j/i, vendor: 'apache', product: 'log4j' },
  { pattern: /^(google\s+)?chrome\b/i, vendor: 'google', product: 'chrome' },
  { pattern: /^firefox\b/i, vendor: 'mozilla', product: 'firefox' },
  { pattern: /^(7[- ]?zip)\b/i, vendor: '7-zip', product: '7-zip' },
  { pattern: /^git\b/i, vendor: 'git-scm', product: 'git' },
  { pattern: /^python(?:\s|$)/i, vendor: 'python', product: 'python' },
]

function cleanVersion(raw: string): string {
  return raw.trim().replace(/^v/i, '').split(/[+ ]/, 1)[0]
}

/** Map an inventory display name to a conservative CPE candidate. */
export function guessNvdCpes(app: InstalledApp): NvdCpe[] {
  const name = (app.name || '').trim()
  const version = cleanVersion(app.version || '')
  if (!name || !version || version.toLowerCase() === 'unknown') return []
  const match = PRODUCT_MAP.find((entry) => entry.pattern.test(name))
  if (!match) return []
  return [{ vendor: match.vendor, product: match.product, version }]
}

function cpeEscape(value: string): string {
  // These mappings are deliberately fixed to known tokens, but escaping the
  // version keeps malformed inventory strings out of the request URL.
  return value.replace(/([\\!"#$%&'()+,/:;<=>?@\[\]^`{|}~ ])/g, '\\$1')
}

export function toCpe23(cpe: NvdCpe): string {
  return [
    'cpe', '2.3', cpe.part ?? 'a', cpeEscape(cpe.vendor), cpeEscape(cpe.product),
    cpeEscape(cpe.version), '*', '*', '*', '*', '*', '*', '*',
  ].join(':')
}

function getCvss(cve: any): { severity?: string; score?: number } {
  const metric = cve?.metrics?.cvssMetricV40?.[0]?.cvssData
    ?? cve?.metrics?.cvssMetricV31?.[0]?.cvssData
    ?? cve?.metrics?.cvssMetricV30?.[0]?.cvssData
    ?? cve?.metrics?.cvssMetricV2?.[0]?.cvssData
  if (!metric || typeof metric !== 'object') return {}
  return {
    severity: typeof metric.baseSeverity === 'string' ? metric.baseSeverity.toLowerCase() : undefined,
    score: typeof metric.baseScore === 'number' ? metric.baseScore : undefined,
  }
}

function parseVulnerabilities(json: any): NvdVulnerability[] {
  if (!Array.isArray(json?.vulnerabilities)) return []
  return json.vulnerabilities
    .map((item: any) => {
      const cve = item?.cve
      const id = typeof cve?.id === 'string' ? cve.id.toUpperCase() : ''
      if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null
      const description = Array.isArray(cve.descriptions)
        ? cve.descriptions.find((d: any) => d?.lang === 'en')?.value
        : undefined
      const cvss = getCvss(cve)
      return {
        id,
        description: typeof description === 'string' ? description.slice(0, 240) : undefined,
        severity: cvss.severity,
        score: cvss.score,
        published: typeof cve.published === 'string' ? cve.published : undefined,
        lastModified: typeof cve.lastModified === 'string' ? cve.lastModified : undefined,
      } satisfies NvdVulnerability
    })
    .filter((v: NvdVulnerability | null): v is NvdVulnerability => v !== null)
    .slice(0, MAX_VULNS_PER_CPE)
}

export async function queryNvd(
  cpe: NvdCpe,
  deps: NvdClientDeps = {},
): Promise<NvdVulnerability[]> {
  const fetchFn = deps.fetchFn ?? fetch
  const endpoint = deps.endpoint ?? DEFAULT_NVD_URL
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const params = new URLSearchParams({ cpeName: toCpe23(cpe), isVulnerable: '', resultsPerPage: String(MAX_VULNS_PER_CPE) })
    const headers: Record<string, string> = { Accept: 'application/json' }
    const apiKey = deps.apiKey ?? process.env.NVD_API_KEY
    if (apiKey) headers.apiKey = apiKey
    const res = await fetchFn(`${endpoint}?${params}`, { signal: controller.signal, headers })
    if (!res.ok) return []
    return parseVulnerabilities(await res.json())
  } catch {
    return []
  } finally {
    clearTimeout(timer)
  }
}

export async function scanAppsWithNvd(
  apps: InstalledApp[],
  deps: NvdClientDeps = {},
): Promise<InventoryFinding[]> {
  const findings: InventoryFinding[] = []
  const seen = new Set<string>()
  let queries = 0
  for (const app of apps) {
    for (const cpe of guessNvdCpes(app)) {
      if (queries >= MAX_QUERIES) return findings
      queries++
      for (const vuln of await queryNvd(cpe, deps)) {
        const key = `${vuln.id}|${app.name}`
        if (seen.has(key)) continue
        seen.add(key)
        const cvss = vuln.score !== undefined ? `:cvss=${vuln.score}` : ''
        findings.push({
          level: 'likely_affected',
          subjectName: vuln.id,
          reason: `nvd_cpe_match:${cpe.vendor}:${cpe.product}@${cpe.version}${cvss}`.slice(0, 200),
          category: 'nvd',
          fixRecommendation: `Update ${app.name} to the latest vendor-supported version`.slice(0, 240),
        })
      }
    }
  }
  return findings
}
