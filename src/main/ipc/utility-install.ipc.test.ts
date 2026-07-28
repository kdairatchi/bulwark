import { beforeEach, describe, expect, it, vi } from 'vitest'

const handleMap = new Map<string, (...args: unknown[]) => unknown>()

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      handleMap.set(channel, handler)
    }),
  },
}))

const mockRunUtilityInstallActions = vi.fn()
const mockUpgradeAllWingetPackages = vi.fn()

vi.mock('../services/utility-install', () => ({
  getInstalledWingetPackages: vi.fn(),
  getUtilityAppCatalog: vi.fn(() => []),
  isWingetAvailable: vi.fn(),
  runUtilityInstallActions: (...args: unknown[]) => mockRunUtilityInstallActions(...args),
  upgradeAllWingetPackages: (...args: unknown[]) => mockUpgradeAllWingetPackages(...args),
}))

import { registerUtilityInstallIpc } from './utility-install.ipc'

function invoke(channel: string, ...args: unknown[]) {
  const handler = handleMap.get(channel)
  if (!handler) throw new Error(`No handler registered for ${channel}`)
  return handler({} /* _event */, ...args)
}

describe('utility-install IPC', () => {
  beforeEach(() => {
    handleMap.clear()
    vi.clearAllMocks()
  })

  it('passes only catalog package IDs to install actions', async () => {
    mockRunUtilityInstallActions.mockResolvedValue({ succeeded: 1, failed: 0, errors: [] })
    registerUtilityInstallIpc(() => null)

    const result = await invoke('utility-install:run', {
      action: 'install',
      ids: ['Google.Chrome', 'Microsoft.Teams', '--source=msstore'],
    })

    expect(result).toEqual({ succeeded: 1, failed: 0, errors: [] })
    expect(mockRunUtilityInstallActions).toHaveBeenCalledOnce()
    expect(mockRunUtilityInstallActions.mock.calls[0][0]).toBe('install')
    expect(mockRunUtilityInstallActions.mock.calls[0][1]).toEqual(['Google.Chrome'])
  })

  it('rejects requests with no catalog package IDs', async () => {
    registerUtilityInstallIpc(() => null)

    const result = await invoke('utility-install:run', {
      action: 'uninstall',
      ids: ['Microsoft.Teams'],
    })

    expect(result).toEqual({
      succeeded: 0,
      failed: 0,
      errors: [{ id: '*', reason: 'No valid package IDs' }],
    })
    expect(mockRunUtilityInstallActions).not.toHaveBeenCalled()
  })

  it('leaves upgrade-all delegated to the dedicated winget flow', async () => {
    mockUpgradeAllWingetPackages.mockResolvedValue({ succeeded: 1, failed: 0, errors: [] })
    registerUtilityInstallIpc(() => null)

    const result = await invoke('utility-install:upgrade-all')

    expect(result).toEqual({ succeeded: 1, failed: 0, errors: [] })
    expect(mockUpgradeAllWingetPackages).toHaveBeenCalledOnce()
  })
})
