import { describe, it, expect, vi } from 'vitest'
import {
  assertDestructiveAllowed,
  isRestoreFrequencyThrottle,
} from './destructive-action-gate'

describe('destructive-action-gate', () => {
  it('detects Windows restore frequency throttle messages', () => {
    expect(isRestoreFrequencyThrottle('A restore point was already created within the last 24 hours')).toBe(true)
    expect(isRestoreFrequencyThrottle('frequency limit 1440 minutes')).toBe(true)
    expect(isRestoreFrequencyThrottle('Access denied')).toBe(false)
  })

  it('allows dry-run without attempting restore', async () => {
    const createRestorePoint = vi.fn()
    const r = await assertDestructiveAllowed({
      description: 'test',
      dryRun: true,
      requireRestorePoint: true,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.skipReason).toBe('dry_run')
    expect(createRestorePoint).not.toHaveBeenCalled()
  })

  it('allows when requireRestorePoint is disabled', async () => {
    const createRestorePoint = vi.fn()
    const r = await assertDestructiveAllowed({
      description: 'test',
      requireRestorePoint: false,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.skipReason).toBe('disabled')
    expect(createRestorePoint).not.toHaveBeenCalled()
  })

  it('allows on Linux/macOS with platform_unsupported', async () => {
    const createRestorePoint = vi.fn()
    const r = await assertDestructiveAllowed({
      description: 'test',
      requireRestorePoint: true,
      deps: { platform: 'linux', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.skipReason).toBe('platform_unsupported')
    expect(createRestorePoint).not.toHaveBeenCalled()
  })

  it('allows when Windows restore succeeds', async () => {
    const createRestorePoint = vi.fn().mockResolvedValue({ success: true })
    const r = await assertDestructiveAllowed({
      description: 'Before clean',
      requireRestorePoint: true,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.restoreAttempted).toBe(true)
    expect(r.restoreSucceeded).toBe(true)
    expect(createRestorePoint).toHaveBeenCalledWith('Before clean')
  })

  it('allows when Windows restore is frequency-throttled', async () => {
    const createRestorePoint = vi.fn().mockResolvedValue({
      success: false,
      error: 'A restore point was already created within the last 24 hours.',
    })
    const r = await assertDestructiveAllowed({
      description: 'Before clean',
      requireRestorePoint: true,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.skipReason).toBe('restore_throttled')
  })

  it('blocks when Windows restore fails for other reasons', async () => {
    const createRestorePoint = vi.fn().mockResolvedValue({
      success: false,
      error: 'Administrator privileges required',
    })
    const r = await assertDestructiveAllowed({
      description: 'Before clean',
      requireRestorePoint: true,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(false)
    expect(r.skipReason).toBe('restore_failed')
    expect(r.error).toMatch(/Administrator/)
  })

  it('allows --force bypass', async () => {
    const createRestorePoint = vi.fn()
    const r = await assertDestructiveAllowed({
      description: 'test',
      requireRestorePoint: true,
      force: true,
      deps: { platform: 'win32', createRestorePoint },
    })
    expect(r.allowed).toBe(true)
    expect(r.skipReason).toBe('force')
    expect(createRestorePoint).not.toHaveBeenCalled()
  })
})
