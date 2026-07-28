import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IPC } from '../../shared/channels'

const handleMap = new Map<string, (...args: unknown[]) => unknown>()

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      handleMap.set(channel, handler)
    }),
  },
}))

const mockGetStatus = vi.fn()
const mockOsCheck = vi.fn()
const mockOsInstall = vi.fn()
const mockPause = vi.fn()
const mockResume = vi.fn()
const mockHelper = vi.fn()

vi.mock('../services/utility-updates', async () => {
  const actual = await vi.importActual<typeof import('../services/utility-updates')>(
    '../services/utility-updates',
  )
  return {
    ...actual,
    getUtilityUpdatesStatus: (...args: unknown[]) => mockGetStatus(...args),
    checkUtilityOsUpdates: (...args: unknown[]) => mockOsCheck(...args),
    installUtilityOsUpdates: (...args: unknown[]) => mockOsInstall(...args),
    pauseUtilityUpdates: (...args: unknown[]) => mockPause(...args),
    resumeUtilityUpdates: (...args: unknown[]) => mockResume(...args),
    runUtilityUpdatesHelper: (...args: unknown[]) => mockHelper(...args),
  }
})

import { registerUtilityUpdatesIpc } from './utility-updates.ipc'

function invoke(channel: string, ...args: unknown[]) {
  const handler = handleMap.get(channel)
  if (!handler) throw new Error(`No handler registered for ${channel}`)
  return handler({} /* _event */, ...args)
}

describe('utility-updates IPC', () => {
  beforeEach(() => {
    handleMap.clear()
    vi.clearAllMocks()
  })

  it('registers status/check/install/pause/resume/helper handlers', async () => {
    mockGetStatus.mockResolvedValue({
      available: true,
      isAdmin: true,
      paused: false,
      pauseExpiresAt: null,
      details: 'ok',
    })
    mockOsCheck.mockResolvedValue({ available: true, updates: [] })
    mockOsInstall.mockResolvedValue({
      success: true,
      installed: 0,
      needsReboot: false,
      resultCode: 0,
      needsAdmin: false,
    })
    mockPause.mockResolvedValue({ success: true, needsAdmin: false })
    mockResume.mockResolvedValue({ success: true, needsAdmin: false })
    mockHelper.mockResolvedValue({
      id: 'open-wu-settings',
      success: true,
      summary: 'opened',
      needsAdmin: false,
      requiresReboot: false,
    })

    registerUtilityUpdatesIpc()

    await expect(invoke(IPC.UTILITY_UPDATES_STATUS)).resolves.toMatchObject({ available: true })
    await expect(invoke(IPC.UTILITY_UPDATES_OS_CHECK)).resolves.toMatchObject({ updates: [] })
    await expect(invoke(IPC.UTILITY_UPDATES_OS_INSTALL)).resolves.toMatchObject({ success: true })
    await expect(invoke(IPC.UTILITY_UPDATES_PAUSE, 7)).resolves.toMatchObject({ success: true })
    expect(mockPause).toHaveBeenCalledWith(7)
    await expect(invoke(IPC.UTILITY_UPDATES_RESUME)).resolves.toMatchObject({ success: true })
    await expect(invoke(IPC.UTILITY_UPDATES_HELPER, 'open-wu-settings')).resolves.toMatchObject({
      id: 'open-wu-settings',
      success: true,
    })
  })

  it('rejects invalid pause days and helper IDs before calling the service', async () => {
    registerUtilityUpdatesIpc()

    await expect(invoke(IPC.UTILITY_UPDATES_PAUSE, 3)).resolves.toEqual({
      success: false,
      needsAdmin: false,
      error: 'Invalid pause duration',
    })
    expect(mockPause).not.toHaveBeenCalled()

    await expect(invoke(IPC.UTILITY_UPDATES_PAUSE, '7')).resolves.toEqual({
      success: false,
      needsAdmin: false,
      error: 'Invalid pause duration',
    })
    expect(mockPause).not.toHaveBeenCalled()

    await expect(invoke(IPC.UTILITY_UPDATES_HELPER, 'not-real')).resolves.toEqual({
      id: 'not-real',
      success: false,
      summary: 'Invalid helper ID',
      error: 'Invalid helper ID',
      needsAdmin: false,
      requiresReboot: false,
    })
    expect(mockHelper).not.toHaveBeenCalled()
  })
})
