import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import type { NetworkRule } from '../../shared/policy'

// Persists user-defined network rules to a small JSON file in userData.

function rulesPath(): string {
  return join(app.getPath('userData'), 'network-rules.json')
}

function isValidRule(raw: unknown): raw is NetworkRule {
  if (!raw || typeof raw !== 'object') return false
  const r = raw as Record<string, unknown>
  if (typeof r.id !== 'string' || typeof r.enabled !== 'boolean') return false
  if (r.action !== 'allow' && r.action !== 'block') return false
  const scope = r.scope as Record<string, unknown> | undefined
  if (!scope || (scope.kind !== 'global' && scope.kind !== 'app')) return false
  if (scope.kind === 'app' && typeof scope.app !== 'string') return false
  if (!r.match || typeof r.match !== 'object') return false
  return true
}

export function loadRules(): NetworkRule[] {
  try {
    const p = rulesPath()
    if (!existsSync(p)) return []
    const parsed = JSON.parse(readFileSync(p, 'utf-8'))
    if (!Array.isArray(parsed)) return []
    return parsed.filter(isValidRule)
  } catch {
    return []
  }
}

export function saveRules(rules: NetworkRule[]): NetworkRule[] {
  const clean = Array.isArray(rules) ? rules.filter(isValidRule).slice(0, 1000) : []
  const dir = app.getPath('userData')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const p = rulesPath()
  const tmp = p + '.tmp'
  writeFileSync(tmp, JSON.stringify(clean), 'utf-8')
  renameSync(tmp, p)
  return clean
}
