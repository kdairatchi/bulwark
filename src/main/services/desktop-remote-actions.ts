/**
 * Non-stub handlers for UPDATE_THREAT_FEEDS, QUARANTINE_FILE, and RESTART_AGENT.
 * Used by the device-command agent (desktop). Android TV has its own path.
 */

import { app } from 'electron'
import { getPlatform } from '../platform'
import { quarantineMalware } from '../ipc/malware-scanner.ipc'
import { syncFilterLists, getFilterListsState, FILTER_LIST_CATALOG } from './filter-lists'
import { getEnabledListIds } from './filter-lists-store'
import { devicePolicyEnforcer } from './device-policy-enforcer'
import { refreshResolverBlocklist } from './dns-blocklist-refresh'
import type { FilterListsState } from '../../shared/filter-lists'

export interface ThreatFeedUpdateDeps {
  syncLists: (ids: string[]) => Promise<FilterListsState>
  getEnabledIds: () => string[]
  getState: (ids: string[]) => FilterListsState
  refreshBlocklist: () => void
  blockDomain: (domain: string) => Promise<Record<string, unknown>>
  reapply: () => Promise<Record<string, unknown>>
  clearManualBlocks: () => void
  getPolicy: () => ReturnType<typeof devicePolicyEnforcer.getPolicy>
  applyPolicy: (policy: NonNullable<ReturnType<typeof devicePolicyEnforcer.getPolicy>>) => Promise<unknown>
}

const defaultThreatFeedDeps = (): ThreatFeedUpdateDeps => ({
  syncLists: (ids) => syncFilterLists(ids),
  getEnabledIds: () => getEnabledListIds(),
  getState: (ids) => getFilterListsState(ids),
  refreshBlocklist: () => refreshResolverBlocklist(),
  blockDomain: (d) => devicePolicyEnforcer.blockDomain(d),
  reapply: async () => devicePolicyEnforcer.reapply(),
  clearManualBlocks: () => devicePolicyEnforcer.clearManualBlocks(),
  getPolicy: () => devicePolicyEnforcer.getPolicy(),
  applyPolicy: (p) => devicePolicyEnforcer.applyRemotePolicy(p),
})

function parseDomainList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter((d): d is string => typeof d === 'string')
    .map((d) => d.trim().toLowerCase())
    .filter((d) => d.length > 0 && d.length <= 253)
    .slice(0, 500)
}

function resolveListIds(parameters: Record<string, unknown>, enabled: string[]): string[] {
  if (Array.isArray(parameters.listIds)) {
    const catalog = new Set(FILTER_LIST_CATALOG.map((l) => l.id))
    const ids = parameters.listIds
      .filter((id): id is string => typeof id === 'string' && catalog.has(id))
    if (ids.length > 0) return [...new Set(ids)]
  }
  return enabled.length > 0 ? enabled : FILTER_LIST_CATALOG.filter((l) => l.enabledByDefault).map((l) => l.id)
}

/**
 * UPDATE_THREAT_FEEDS
 * - syncLists (default true): download/cache enabled filter lists (URLhaus, …)
 * - domains[] (+ optional replace): push extra domains into remote blocklist (Android parity)
 * - listIds[]: override which catalog lists to sync
 */
export async function executeUpdateThreatFeeds(
  parameters: Record<string, unknown> = {},
  deps: ThreatFeedUpdateDeps = defaultThreatFeedDeps(),
): Promise<Record<string, unknown>> {
  const syncLists = parameters.syncLists !== false
  const domains = parseDomainList(parameters.domains)
  const replace = parameters.replace === true
  const enabled = deps.getEnabledIds()
  const listIds = resolveListIds(parameters, enabled)

  let state: FilterListsState = deps.getState(enabled)
  const errors: string[] = []

  if (syncLists && listIds.length > 0) {
    try {
      state = await deps.syncLists(listIds)
      for (const l of state.lists) {
        if (l.lastError) errors.push(`${l.id}: ${l.lastError}`)
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err))
      state = deps.getState(enabled)
    }
  }

  try {
    deps.refreshBlocklist()
  } catch {
    /* resolver not initialized yet — reapply still updates enforcer state */
  }

  let domainsAdded = 0
  if (domains.length > 0) {
    // replace: wipe prior remote/manual blocks, then add the provided domains
    // (filter-list cache is untouched — Android parity for the domains[] payload).
    if (replace) {
      deps.clearManualBlocks()
      const policy = deps.getPolicy()
      if (policy) {
        await deps.applyPolicy({ ...policy, blockedDomains: [] })
      }
    }
    for (const d of domains) {
      const r = await deps.blockDomain(d)
      if (r.applied === true) domainsAdded++
    }
  } else {
    await deps.reapply()
  }

  const updated = syncLists || domainsAdded > 0 || domains.length > 0
  return {
    ok: errors.length === 0 || state.totalDomains > 0 || domainsAdded > 0,
    stub: false,
    type: 'UPDATE_THREAT_FEEDS',
    updated,
    syncedLists: syncLists ? listIds : [],
    totalDomains: state.totalDomains,
    domainsAdded,
    blocklistSize: state.totalDomains + devicePolicyEnforcer.remoteBlockedDomains().length,
    errors: errors.slice(0, 10),
    parameters,
  }
}

export interface QuarantineFileDeps {
  isAllowed: (path: string) => boolean
  quarantine: (paths: string[]) => Promise<{ succeeded: number; failed: number; errors: Array<{ path: string; reason: string }> }>
}

const defaultQuarantineDeps = (): QuarantineFileDeps => ({
  isAllowed: (p) => getPlatform().malwarePaths.isAllowedMalwarePath(p),
  quarantine: (paths) => quarantineMalware(paths),
})

function parsePaths(parameters: Record<string, unknown>): string[] {
  if (typeof parameters.path === 'string' && parameters.path.trim()) {
    return [parameters.path.trim()]
  }
  if (Array.isArray(parameters.paths)) {
    return parameters.paths
      .filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
      .map((p) => p.trim())
      .slice(0, 100)
  }
  return []
}

/** QUARANTINE_FILE — path(s) must be under platform malware allowlist (/tmp, Downloads, …). */
export async function executeQuarantineFile(
  parameters: Record<string, unknown> = {},
  deps: QuarantineFileDeps = defaultQuarantineDeps(),
): Promise<Record<string, unknown>> {
  const paths = parsePaths(parameters)
  if (paths.length === 0) {
    return {
      ok: false,
      stub: false,
      type: 'QUARANTINE_FILE',
      applied: false,
      reason: 'missing path or paths',
      parameters,
    }
  }
  if (paths.some((p) => p.length > 500)) {
    return {
      ok: false,
      stub: false,
      type: 'QUARANTINE_FILE',
      applied: false,
      reason: 'path too long',
      parameters,
    }
  }
  const denied = paths.filter((p) => !deps.isAllowed(p))
  if (denied.length > 0) {
    return {
      ok: false,
      stub: false,
      type: 'QUARANTINE_FILE',
      applied: false,
      reason: 'path outside allowed directories',
      denied: denied.slice(0, 5),
      parameters,
    }
  }

  try {
    const result = await deps.quarantine(paths)
    return {
      ok: result.failed === 0 && result.succeeded > 0,
      stub: false,
      type: 'QUARANTINE_FILE',
      applied: result.succeeded > 0,
      succeeded: result.succeeded,
      failed: result.failed,
      errors: result.errors.map((e) => ({ path: e.path, reason: e.reason.slice(0, 200) })),
      parameters,
    }
  } catch (err) {
    return {
      ok: false,
      stub: false,
      type: 'QUARANTINE_FILE',
      applied: false,
      reason: err instanceof Error ? err.message : String(err),
      parameters,
    }
  }
}

export interface RestartAgentDeps {
  alreadyScheduled: () => boolean
  markScheduled: () => void
  schedule: (fn: () => void, delayMs: number) => void
  releaseLock: () => void
  relaunch: (opts: { args: string[] }) => void
  exit: (code: number) => void
  delayMs: number
  argv: string[]
}

let restartScheduled = false

/** Test-only: clear the one-shot restart guard. */
export function resetRestartAgentSchedule(): void {
  restartScheduled = false
}

const defaultRestartDeps = (): RestartAgentDeps => ({
  alreadyScheduled: () => restartScheduled,
  markScheduled: () => { restartScheduled = true },
  schedule: (fn, delayMs) => { setTimeout(fn, delayMs) },
  releaseLock: () => {
    try { app.releaseSingleInstanceLock() } catch { /* not held / tests */ }
  },
  relaunch: (opts) => { app.relaunch(opts) },
  exit: (code) => { app.exit(code) },
  delayMs: 1000,
  argv: process.argv.slice(1),
})

/**
 * RESTART_AGENT — schedule a process relaunch after the command result is posted.
 * Returns immediately with `scheduled: true`; never exits synchronously.
 */
export function executeRestartAgent(
  parameters: Record<string, unknown> = {},
  deps: RestartAgentDeps = defaultRestartDeps(),
): Record<string, unknown> {
  if (deps.alreadyScheduled()) {
    return {
      ok: true,
      stub: false,
      type: 'RESTART_AGENT',
      scheduled: true,
      reason: 'already_scheduled',
      parameters,
    }
  }
  deps.markScheduled()
  deps.schedule(() => {
    try {
      deps.releaseLock()
      deps.relaunch({ args: deps.argv })
      deps.exit(0)
    } catch {
      /* best-effort — agent may already be exiting */
    }
  }, deps.delayMs)
  return {
    ok: true,
    stub: false,
    type: 'RESTART_AGENT',
    scheduled: true,
    parameters,
  }
}
