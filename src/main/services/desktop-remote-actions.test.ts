import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  executeUpdateThreatFeeds,
  executeQuarantineFile,
  executeRestartAgent,
  resetRestartAgentSchedule,
  type ThreatFeedUpdateDeps,
} from './desktop-remote-actions'

function feedDeps(overrides: Partial<ThreatFeedUpdateDeps> = {}): ThreatFeedUpdateDeps {
  const blocked: string[] = []
  return {
    syncLists: vi.fn(async () => ({
      lists: [{ id: 'urlhaus', name: 'URLhaus', description: '', category: 'malware', enabled: true, domainCount: 42, cached: true, updatedAt: '2026-01-01' }],
      totalDomains: 42,
    })),
    getEnabledIds: () => ['urlhaus'],
    getState: () => ({ lists: [], totalDomains: 42 }),
    refreshBlocklist: vi.fn(),
    blockDomain: vi.fn(async (d: string) => {
      blocked.push(d)
      return { ok: true, applied: true, domain: d }
    }),
    reapply: vi.fn(async () => ({ mode: 'blocklist', domainCount: blocked.length })),
    clearManualBlocks: vi.fn(),
    getPolicy: () => null,
    applyPolicy: vi.fn(async () => ({})),
    ...overrides,
  }
}

describe('executeUpdateThreatFeeds', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('syncs filter lists and is not a stub', async () => {
    const deps = feedDeps()
    const r = await executeUpdateThreatFeeds({ syncLists: true }, deps)
    expect(r.stub).toBe(false)
    expect(r.updated).toBe(true)
    expect(r.totalDomains).toBe(42)
    expect(deps.syncLists).toHaveBeenCalledWith(['urlhaus'])
    expect(deps.refreshBlocklist).toHaveBeenCalled()
    expect(deps.reapply).toHaveBeenCalled()
  })

  it('adds domains without syncing when syncLists=false', async () => {
    const deps = feedDeps()
    const r = await executeUpdateThreatFeeds({
      syncLists: false,
      domains: ['evil.example', 'bad.test'],
    }, deps)
    expect(r.stub).toBe(false)
    expect(r.domainsAdded).toBe(2)
    expect(deps.syncLists).not.toHaveBeenCalled()
    expect(deps.blockDomain).toHaveBeenCalledTimes(2)
  })

  it('replace clears manual blocks before adding domains', async () => {
    const deps = feedDeps()
    await executeUpdateThreatFeeds({
      syncLists: false,
      replace: true,
      domains: ['only.evil'],
    }, deps)
    expect(deps.clearManualBlocks).toHaveBeenCalled()
    expect(deps.blockDomain).toHaveBeenCalledWith('only.evil')
  })
})

describe('executeQuarantineFile', () => {
  it('rejects missing path', async () => {
    const r = await executeQuarantineFile({}, {
      isAllowed: () => true,
      quarantine: async () => ({ succeeded: 0, failed: 0, errors: [] }),
    })
    expect(r.ok).toBe(false)
    expect(r.stub).toBe(false)
    expect(r.reason).toMatch(/missing path/i)
  })

  it('rejects paths outside allowlist', async () => {
    const r = await executeQuarantineFile({ path: '/etc/passwd' }, {
      isAllowed: () => false,
      quarantine: async () => ({ succeeded: 0, failed: 0, errors: [] }),
    })
    expect(r.ok).toBe(false)
    expect(r.applied).toBe(false)
    expect(r.reason).toMatch(/outside allowed/i)
  })

  it('quarantines allowed paths', async () => {
    const quarantine = vi.fn(async () => ({ succeeded: 1, failed: 0, errors: [] }))
    const r = await executeQuarantineFile({ path: '/tmp/evil.bin' }, {
      isAllowed: (p) => p.startsWith('/tmp/'),
      quarantine,
    })
    expect(r.stub).toBe(false)
    expect(r.ok).toBe(true)
    expect(r.applied).toBe(true)
    expect(r.succeeded).toBe(1)
    expect(quarantine).toHaveBeenCalledWith(['/tmp/evil.bin'])
  })

  it('accepts paths array', async () => {
    const quarantine = vi.fn(async () => ({ succeeded: 2, failed: 0, errors: [] }))
    const r = await executeQuarantineFile({ paths: ['/tmp/a', '/tmp/b'] }, {
      isAllowed: () => true,
      quarantine,
    })
    expect(r.succeeded).toBe(2)
    expect(quarantine).toHaveBeenCalledWith(['/tmp/a', '/tmp/b'])
  })
})

describe('executeRestartAgent', () => {
  beforeEach(() => {
    resetRestartAgentSchedule()
  })

  it('schedules relaunch and is not a stub', () => {
    const relaunch = vi.fn()
    const exit = vi.fn()
    const releaseLock = vi.fn()
    const scheduled: Array<() => void> = []
    const r = executeRestartAgent({}, {
      alreadyScheduled: () => false,
      markScheduled: () => {},
      schedule: (fn) => { scheduled.push(fn) },
      releaseLock,
      relaunch,
      exit,
      delayMs: 10,
      argv: ['--app'],
    })
    expect(r.stub).toBe(false)
    expect(r.ok).toBe(true)
    expect(r.scheduled).toBe(true)
    expect(scheduled).toHaveLength(1)
    scheduled[0]!()
    expect(releaseLock).toHaveBeenCalled()
    expect(relaunch).toHaveBeenCalledWith({ args: ['--app'] })
    expect(exit).toHaveBeenCalledWith(0)
  })

  it('is idempotent when already scheduled', () => {
    let flagged = false
    const schedule = vi.fn()
    const first = executeRestartAgent({}, {
      alreadyScheduled: () => flagged,
      markScheduled: () => { flagged = true },
      schedule,
      releaseLock: vi.fn(),
      relaunch: vi.fn(),
      exit: vi.fn(),
      delayMs: 10,
      argv: [],
    })
    const second = executeRestartAgent({}, {
      alreadyScheduled: () => flagged,
      markScheduled: () => { flagged = true },
      schedule,
      releaseLock: vi.fn(),
      relaunch: vi.fn(),
      exit: vi.fn(),
      delayMs: 10,
      argv: [],
    })
    expect(first.scheduled).toBe(true)
    expect(second.reason).toBe('already_scheduled')
    expect(schedule).toHaveBeenCalledTimes(1)
  })
})
