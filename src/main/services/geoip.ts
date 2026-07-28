// IP → country lookup service (DB-IP Lite country database).
//
// The CSV is `startIP,endIP,CC` with dotted IPv4 addresses, sorted by start.
// We parse it into parallel typed arrays and binary-search on lookup. Downloaded
// on demand and cached to userData so it works offline afterwards.

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, statSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import { ipv4ToNumber } from './threat-monitor'
import type { GeoipStatus } from '../../shared/geoip'
import { GEOIP_ATTRIBUTION } from '../../shared/geoip'

const DB_URL = 'https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv'
const MAX_BYTES = 40 * 1024 * 1024
const FETCH_TIMEOUT_MS = 45_000

interface Ranges {
  starts: Uint32Array
  ends: Uint32Array
  cc: string[]
}

let loaded: Ranges | null = null

function dbPath(): string {
  const dir = join(app.getPath('userData'), 'geoip')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return join(dir, 'dbip-country-ipv4.csv')
}

/** Parse the DB-IP CSV text into sorted range arrays. Exported for testing. */
export function parseGeoipCsv(text: string): Ranges {
  const lines = text.split(/\r?\n/)
  const starts: number[] = []
  const ends: number[] = []
  const cc: string[] = []
  for (const line of lines) {
    if (!line) continue
    const c1 = line.indexOf(',')
    if (c1 === -1) continue
    const c2 = line.indexOf(',', c1 + 1)
    if (c2 === -1) continue
    const s = ipv4ToNumber(line.slice(0, c1))
    const e = ipv4ToNumber(line.slice(c1 + 1, c2))
    const country = line.slice(c2 + 1).trim().toUpperCase()
    if (s === null || e === null || country.length !== 2) continue
    starts.push(s)
    ends.push(e)
    cc.push(country)
  }
  return { starts: Uint32Array.from(starts), ends: Uint32Array.from(ends), cc }
}

function ensureLoaded(): Ranges | null {
  if (loaded) return loaded
  const p = dbPath()
  if (!existsSync(p)) return null
  try {
    loaded = parseGeoipCsv(readFileSync(p, 'utf-8'))
    return loaded
  } catch {
    return null
  }
}

/** Look up the ISO country code for an IPv4 address, or null. Pure over ranges. */
export function lookupCountryIn(ranges: Ranges, ip: string): string | null {
  const num = ipv4ToNumber(ip)
  if (num === null) return null
  const { starts, ends, cc } = ranges
  let lo = 0
  let hi = starts.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1
    if (num < starts[mid]) hi = mid - 1
    else if (num > ends[mid]) lo = mid + 1
    else return cc[mid]
  }
  return null
}

/** Look up a country using the loaded DB (returns null if not synced yet). */
export function lookupCountry(ip: string): string | null {
  const ranges = ensureLoaded()
  if (!ranges) return null
  return lookupCountryIn(ranges, ip)
}

export function getGeoipStatus(): GeoipStatus {
  const ranges = ensureLoaded()
  let updatedAt: string | null = null
  try {
    const p = dbPath()
    if (existsSync(p)) updatedAt = new Date(statSync(p).mtimeMs).toISOString()
  } catch { /* ignore */ }
  return {
    ready: !!ranges,
    ranges: ranges ? ranges.cc.length : 0,
    updatedAt,
    attribution: GEOIP_ATTRIBUTION,
  }
}

/** Download + cache the DB and reload it into memory. */
export async function syncGeoip(): Promise<GeoipStatus> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(DB_URL, { signal: controller.signal })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const text = await res.text()
    if (text.length > MAX_BYTES) throw new Error('geoip db too large')
    const p = dbPath()
    const tmp = p + '.tmp'
    writeFileSync(tmp, text, 'utf-8')
    renameSync(tmp, p)
    loaded = parseGeoipCsv(text)
  } finally {
    clearTimeout(timeout)
  }
  return getGeoipStatus()
}
