import { describe, it, expect, vi, beforeEach } from 'vitest'

const mockCleanItems = vi.fn()
const mockAssertDestructiveAllowed = vi.fn()
const mockGetSettings = vi.fn()

vi.mock('./file-utils', () => ({
  cleanItems: (...args: unknown[]) => mockCleanItems(...args),
}))

vi.mock('./destructive-action-gate', () => ({
  assertDestructiveAllowed: (...args: unknown[]) => mockAssertDestructiveAllowed(...args),
}))

vi.mock('./settings-store', () => ({
  getSettings: () => mockGetSettings(),
}))

import { gatedCleanItems, blockedCleanResult, assertCleanAllowed } from './gated-clean'

describe('gated-clean', () => {
  beforeEach(() => {
    mockCleanItems.mockReset()
    mockAssertDestructiveAllowed.mockReset()
    mockGetSettings.mockReset()
    mockGetSettings.mockReturnValue({ cleaner: { requireRestorePoint: false } })
    mockAssertDestructiveAllowed.mockResolvedValue({
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'disabled',
    })
    mockCleanItems.mockResolvedValue({
      totalCleaned: 10,
      filesDeleted: 1,
      filesSkipped: 0,
      errors: [],
      needsElevation: false,
    })
  })

  it('passes through to cleanItems when gate allows', async () => {
    const result = await gatedCleanItems(['a'], undefined, 'local', {})
    expect(result.filesDeleted).toBe(1)
    expect(mockCleanItems).toHaveBeenCalledWith(['a'], undefined, 'local', { dryRun: false })
  })

  it('forwards dryRun to cleanItems', async () => {
    mockAssertDestructiveAllowed.mockResolvedValue({
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'dry_run',
    })
    mockCleanItems.mockResolvedValue({
      totalCleaned: 10,
      filesDeleted: 1,
      filesSkipped: 0,
      errors: [],
      needsElevation: false,
      dryRun: true,
    })
    const result = await gatedCleanItems(['a'], undefined, 'cloud', { dryRun: true })
    expect(result.dryRun).toBe(true)
    expect(mockCleanItems).toHaveBeenCalledWith(['a'], undefined, 'cloud', { dryRun: true })
  })

  it('does not call cleanItems when restore gate blocks', async () => {
    mockGetSettings.mockReturnValue({ cleaner: { requireRestorePoint: true } })
    mockAssertDestructiveAllowed.mockResolvedValue({
      allowed: false,
      restoreAttempted: true,
      restoreSucceeded: false,
      skipReason: 'restore_failed',
      error: 'Administrator privileges required',
    })
    const result = await gatedCleanItems(['a'])
    expect(result.blockedByRestoreGate).toBe(true)
    expect(result.filesDeleted).toBe(0)
    expect(result.errors[0].reason).toMatch(/Administrator/)
    expect(mockCleanItems).not.toHaveBeenCalled()
  })

  it('assertCleanAllowed reads requireRestorePoint from settings', async () => {
    mockGetSettings.mockReturnValue({ cleaner: { requireRestorePoint: true } })
    await assertCleanAllowed({ dryRun: false })
    expect(mockAssertDestructiveAllowed).toHaveBeenCalledWith(
      expect.objectContaining({ requireRestorePoint: true, dryRun: false }),
    )
  })

  it('blockedCleanResult marks blockedByRestoreGate', () => {
    const r = blockedCleanResult({
      allowed: false,
      restoreAttempted: true,
      restoreSucceeded: false,
      skipReason: 'restore_failed',
      error: 'nope',
    })
    expect(r.blockedByRestoreGate).toBe(true)
    expect(r.errors[0].reason).toBe('nope')
  })
})
