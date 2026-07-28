/**
 * Offline Living-off-the-Land + technique grep scanner.
 * Catalog: rules/security/lolbins.json — not a live CVE/zero-day feed.
 */

import { readFileSync, statSync } from 'fs'
import path from 'path'
import { execFile } from 'child_process'
import { promisify } from 'util'
import type { MalwareThreat } from '../../shared/types'
import type { InventoryFinding } from './desktop-inventory'

const execFileAsync = promisify(execFile)

export type LolbinCategory = 'lolbin' | 'lolscript' | 'technique'
export type LolbinSurface = 'cmdline' | 'script' | 'lnk' | 'registry' | 'task' | 'content'
export type LolbinSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface LolbinRule {
  id: string
  category: LolbinCategory
  platforms: Array<'win32' | 'darwin' | 'linux' | 'all'>
  binPatterns?: string[]
  argsPattern?: string
  combinedPattern?: string
  surfaces: LolbinSurface[]
  severity: LolbinSeverity
  detectionName: string
  details: string
  mitre?: string[]
  minHits?: number
}

export interface LolbinCatalog {
  version: string
  updatedAt: string
  description?: string
  rules: LolbinRule[]
}

export interface LolbinHit {
  ruleId: string
  category: LolbinCategory
  detectionName: string
  severity: LolbinSeverity
  details: string
  mitre: string[]
  surface: LolbinSurface
  sample: string
  path?: string
}

interface CompiledRule extends LolbinRule {
  binRes: RegExp[]
  argsRe: RegExp | null
  combinedRe: RegExp | null
}

let cached: { catalogPath: string; mtimeMs: number; rules: CompiledRule[]; version: string } | null = null

function defaultCatalogPath(): string {
  return path.resolve(__dirname, '../../../rules/security/lolbins.json')
}

function compileRegex(source: string, id: string): RegExp {
  try {
    // Catalog patterns may include PCRE-style (?i); JS uses the flags arg instead.
    const cleaned = source.replace(/^\(\?i\)/, '')
    return new RegExp(cleaned, 'i')
  } catch (err) {
    throw new Error(`Invalid regex in lolbin rule ${id}: ${(err as Error).message}`)
  }
}

export function loadLolbinCatalog(catalogPath: string = defaultCatalogPath()): {
  version: string
  rules: CompiledRule[]
} {
  const raw = readFileSync(catalogPath, 'utf-8')
  const catalog = JSON.parse(raw) as LolbinCatalog
  if (!Array.isArray(catalog.rules)) throw new Error('lolbins catalog missing rules[]')
  const rules = catalog.rules.map((r) => ({
    ...r,
    binRes: (r.binPatterns ?? []).map((p) => compileRegex(p, r.id)),
    argsRe: r.argsPattern ? compileRegex(r.argsPattern, r.id) : null,
    combinedRe: r.combinedPattern ? compileRegex(r.combinedPattern, r.id) : null,
  }))
  return { version: catalog.version, rules }
}

function getCompiledRules(catalogPath?: string): CompiledRule[] {
  const p = catalogPath ?? defaultCatalogPath()
  try {
    const { mtimeMs } = statSync(p)
    if (cached && cached.catalogPath === p && cached.mtimeMs === mtimeMs) return cached.rules
    const loaded = loadLolbinCatalog(p)
    cached = { catalogPath: p, mtimeMs, rules: loaded.rules, version: loaded.version }
    return loaded.rules
  } catch {
    // Tests / missing file — empty set rather than crash scanners.
    return cached?.rules ?? []
  }
}

/** Reset cache (tests). */
export function resetLolbinCatalogCache(): void {
  cached = null
}

function platformMatches(rule: LolbinRule, platform: NodeJS.Platform): boolean {
  return rule.platforms.includes('all') || rule.platforms.includes(platform as 'win32' | 'darwin' | 'linux')
}

function splitCommandLine(cmdline: string): { bin: string; args: string } {
  const trimmed = cmdline.trim()
  if (!trimmed) return { bin: '', args: '' }
  // Handle quoted executable paths.
  const m = trimmed.match(/^"([^"]+)"\s*(.*)$/) || trimmed.match(/^'([^']+)'\s*(.*)$/)
  if (m) return { bin: m[1], args: m[2] ?? '' }
  const sp = trimmed.search(/\s/)
  if (sp < 0) return { bin: trimmed, args: '' }
  return { bin: trimmed.slice(0, sp), args: trimmed.slice(sp + 1) }
}

function basenameLike(bin: string): string {
  const norm = bin.replace(/\//g, '\\')
  const parts = norm.split('\\')
  return parts[parts.length - 1] || bin
}

function ruleMatchesCommand(rule: CompiledRule, cmdline: string): boolean {
  if (rule.combinedRe) return rule.combinedRe.test(cmdline)
  const { bin, args } = splitCommandLine(cmdline)
  const base = basenameLike(bin)
  const binOk = rule.binRes.length === 0
    || rule.binRes.some((re) => re.test(bin) || re.test(base))
  if (!binOk) return false
  if (rule.argsRe && !rule.argsRe.test(args) && !rule.argsRe.test(cmdline)) return false
  return true
}

function ruleMatchesContent(rule: CompiledRule, content: string): boolean {
  if (rule.combinedRe) return rule.combinedRe.test(content)
  // For free-form content, require combined OR (any bin mention + args).
  if (rule.binRes.length && rule.argsRe) {
    const binHit = rule.binRes.some((re) => re.test(content))
    return binHit && rule.argsRe.test(content)
  }
  if (rule.binRes.length) return rule.binRes.some((re) => re.test(content))
  if (rule.argsRe) return rule.argsRe.test(content)
  return false
}

export function matchLolbinCommand(
  cmdline: string,
  opts: { platform?: NodeJS.Platform; surface?: LolbinSurface; catalogPath?: string } = {},
): LolbinHit[] {
  const platform = opts.platform ?? process.platform
  const surface: LolbinSurface = opts.surface ?? 'cmdline'
  const rules = getCompiledRules(opts.catalogPath)
  const hits: LolbinHit[] = []
  const sample = cmdline.trim().slice(0, 400)
  if (!sample) return hits
  for (const rule of rules) {
    if (!platformMatches(rule, platform)) continue
    if (!rule.surfaces.includes(surface)) continue
    if (ruleMatchesCommand(rule, sample)) {
      hits.push({
        ruleId: rule.id,
        category: rule.category,
        detectionName: rule.detectionName,
        severity: rule.severity,
        details: rule.details,
        mitre: rule.mitre ?? [],
        surface,
        sample,
      })
    }
  }
  return hits
}

export function matchLolbinContent(
  content: string,
  surface: LolbinSurface,
  opts: { platform?: NodeJS.Platform; path?: string; catalogPath?: string } = {},
): LolbinHit[] {
  const platform = opts.platform ?? process.platform
  const rules = getCompiledRules(opts.catalogPath)
  const hits: LolbinHit[] = []
  const text = content.slice(0, 200_000)
  if (!text.trim()) return hits
  for (const rule of rules) {
    if (!platformMatches(rule, platform)) continue
    if (!rule.surfaces.includes(surface) && !rule.surfaces.includes('content')) continue
    const ok = surface === 'cmdline'
      ? ruleMatchesCommand(rule, text)
      : ruleMatchesContent(rule, text)
    if (ok) {
      hits.push({
        ruleId: rule.id,
        category: rule.category,
        detectionName: rule.detectionName,
        severity: rule.severity,
        details: rule.details,
        mitre: rule.mitre ?? [],
        surface,
        sample: text.replace(/\s+/g, ' ').trim().slice(0, 400),
        path: opts.path,
      })
    }
  }
  return hits
}

export function hitsToMalwareThreats(hits: LolbinHit[], pathStr: string, fileName: string): MalwareThreat[] {
  return hits.map((h, i) => ({
    id: `lolbin_${h.ruleId}_${i}_${Date.now()}`,
    path: pathStr || h.path || h.sample,
    fileName: fileName || path.basename(pathStr || 'cmdline'),
    size: 0,
    detectionName: h.detectionName,
    severity: h.severity,
    source: 'heuristic' as const,
    details: `${h.details}${h.mitre.length ? ` [${h.mitre.join(', ')}]` : ''} · ${h.sample}`,
    selected: true,
  }))
}

export function hitsToCloudFindings(hits: LolbinHit[]): InventoryFinding[] {
  return hits.map((h) => ({
    level: h.severity === 'critical' || h.severity === 'high' ? 'likely_affected' : 'potential_match',
    subjectName: h.detectionName,
    reason: h.ruleId,
    category: h.category === 'technique' ? 'technique' : 'lolbin',
  }))
}

export interface ProcessCmdline {
  pid: number
  cmdline: string
}

/** Best-effort process cmdline inventory for LotL grep (bounded, offline). */
export async function collectProcessCommandLines(): Promise<ProcessCmdline[]> {
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execFileAsync(
        'powershell.exe',
        [
          '-NoProfile', '-NonInteractive', '-Command',
          'Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress',
        ],
        { timeout: 12_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      )
      const parsed = JSON.parse(stdout || '[]') as Array<{ ProcessId?: number; CommandLine?: string }>
      const arr = Array.isArray(parsed) ? parsed : [parsed]
      return arr
        .filter((p) => typeof p.CommandLine === 'string' && p.CommandLine.trim())
        .map((p) => ({ pid: Number(p.ProcessId) || 0, cmdline: String(p.CommandLine) }))
        .slice(0, 800)
    }
    const { stdout } = await execFileAsync(
      'ps',
      process.platform === 'darwin'
        ? ['-ax', '-o', 'pid=,command=']
        : ['-axw', '-o', 'pid=,args='],
      { timeout: 8_000, maxBuffer: 8 * 1024 * 1024 },
    )
    const out: ProcessCmdline[] = []
    for (const line of stdout.split('\n')) {
      const m = line.trim().match(/^(\d+)\s+(.+)$/)
      if (!m) continue
      out.push({ pid: Number(m[1]), cmdline: m[2] })
      if (out.length >= 800) break
    }
    return out
  } catch {
    return []
  }
}

/** Scan live process cmdlines with the LotL catalog. */
export async function scanProcessLolbins(opts?: {
  platform?: NodeJS.Platform
  catalogPath?: string
}): Promise<LolbinHit[]> {
  const procs = await collectProcessCommandLines()
  const hits: LolbinHit[] = []
  const seen = new Set<string>()
  for (const p of procs) {
    for (const h of matchLolbinCommand(p.cmdline, {
      platform: opts?.platform,
      surface: 'cmdline',
      catalogPath: opts?.catalogPath,
    })) {
      const key = `${h.ruleId}|${h.sample}`
      if (seen.has(key)) continue
      seen.add(key)
      hits.push({ ...h, path: `pid:${p.pid}` })
      if (hits.length >= 100) return hits
    }
  }
  return hits
}

export function getLolbinCatalogInfo(catalogPath?: string): { version: string; ruleCount: number } {
  const loaded = loadLolbinCatalog(catalogPath ?? defaultCatalogPath())
  return { version: loaded.version, ruleCount: loaded.rules.length }
}
