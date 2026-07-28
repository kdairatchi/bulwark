import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  apply: vi.fn<() => Promise<void>>(),
  revert: vi.fn<() => Promise<void>>(),
  check: vi.fn<() => Promise<boolean>>(),
  createRestorePoint: vi.fn(),
}))

vi.mock('./restore-point', () => ({
  createRestorePoint: mocks.createRestorePoint,
}))

vi.mock('./utility-tweaks.catalog', () => ({
  UTILITY_TWEAK_CATALOG: [{
    id: 'mock-tweak',
    name: 'Mock tweak',
    description: 'Mock reversible tweak',
    group: 'essential',
    requiresAdmin: false,
    check: mocks.check,
    apply: mocks.apply,
    revert: mocks.revert,
  }],
}))

import { applyTweaks } from './utility-tweaks'

const originalPlatform = process.platform

describe('applyTweaks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
  })

  it('stops before applying any tweak when restore point creation fails', async () => {
    mocks.createRestorePoint.mockResolvedValue({
      success: false,
      error: 'System Protection is turned off',
    })

    const result = await applyTweaks(['mock-tweak'])

    expect(result.succeeded).toBe(0)
    expect(result.failed).toBe(1)
    expect(result.errors[0].reason).toContain('Restore point failed')
    expect(result.restorePoint).toEqual({
      success: false,
      error: 'System Protection is turned off',
    })
    expect(mocks.apply).not.toHaveBeenCalled()
  })

  it('creates the restore point before applying selected tweaks', async () => {
    const order: string[] = []
    mocks.createRestorePoint.mockImplementation(async () => {
      order.push('restore-point')
      return { success: true }
    })
    mocks.apply.mockImplementation(async () => {
      order.push('apply')
    })

    const result = await applyTweaks(['mock-tweak'])

    expect(result).toMatchObject({
      succeeded: 1,
      failed: 0,
      errors: [],
      restorePoint: { success: true },
    })
    expect(order).toEqual(['restore-point', 'apply'])
  })
})
