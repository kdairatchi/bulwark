import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import { FILTER_LIST_CATALOG } from './filter-lists'

// Persists which filter lists the user has enabled. Defaults to the catalog's
// enabledByDefault selection on first run.

function configPath(): string {
  return join(app.getPath('userData'), 'filter-lists-config.json')
}

const catalogIds = new Set(FILTER_LIST_CATALOG.map((l) => l.id))

export function getEnabledListIds(): string[] {
  try {
    const p = configPath()
    if (existsSync(p)) {
      const parsed = JSON.parse(readFileSync(p, 'utf-8'))
      if (Array.isArray(parsed?.enabledIds)) {
        return parsed.enabledIds.filter((id: unknown): id is string => typeof id === 'string' && catalogIds.has(id))
      }
    }
  } catch {
    /* fall through to defaults */
  }
  return FILTER_LIST_CATALOG.filter((l) => l.enabledByDefault).map((l) => l.id)
}

export function setEnabledListIds(ids: string[]): string[] {
  const clean = [...new Set(ids)].filter((id) => catalogIds.has(id))
  const dir = app.getPath('userData')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const p = configPath()
  const tmp = p + '.tmp'
  writeFileSync(tmp, JSON.stringify({ enabledIds: clean }), 'utf-8')
  renameSync(tmp, p)
  return clean
}
