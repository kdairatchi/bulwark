import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const handleMap = new Map<string, (...args: unknown[]) => unknown>()
const mockOpenPath = vi.fn()
const mockOpenExternal = vi.fn()
const mockExistsSync = vi.fn()

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      handleMap.set(channel, handler)
    }),
  },
  shell: {
    openPath: (...args: unknown[]) => mockOpenPath(...args),
    openExternal: (...args: unknown[]) => mockOpenExternal(...args),
  },
}))

vi.mock('fs', () => ({
  existsSync: (...args: unknown[]) => mockExistsSync(...args),
}))

vi.mock('../services/utility-tweaks', () => ({
  applyTweaks: vi.fn(),
  getCatalog: vi.fn(() => []),
  getUtilityPowerPlan: vi.fn(),
  revertTweaks: vi.fn(),
  scanTweaks: vi.fn(),
  setUtilityPowerPlan: vi.fn(),
  UTILITY_POWER_PLAN_TARGETS: ['balanced', 'high-performance'],
  validateUtilityTweakIds: vi.fn(),
}))

import {
  getResolvedShutUp10Roots,
  getShutUp10Candidates,
  isShutUp10CandidatePathAllowed,
  registerUtilityTweaksIpc,
} from './utility-tweaks.ipc'

function invoke(channel: string, ...args: unknown[]) {
  const handler = handleMap.get(channel)
  if (!handler) throw new Error(`No handler registered for ${channel}`)
  return handler({} /* _event */, ...args)
}

describe('ShutUp10 path hardening', () => {
  const originalPlatform = process.platform
  const originalProgramFiles = process.env.ProgramFiles
  const originalProgramFilesX86 = process.env['ProgramFiles(x86)']
  const originalLocalAppData = process.env.LOCALAPPDATA

  beforeEach(() => {
    handleMap.clear()
    vi.clearAllMocks()
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
    process.env.ProgramFiles = originalProgramFiles
    process.env['ProgramFiles(x86)'] = originalProgramFilesX86
    process.env.LOCALAPPDATA = originalLocalAppData
  })

  it('uses only absolute roots without parent-directory segments', () => {
    const env = {
      ProgramFiles: '/tmp/ProgramFiles',
      'ProgramFiles(x86)': 'relative-root',
      LOCALAPPDATA: '/tmp/LocalAppData/..',
    }

    expect(getResolvedShutUp10Roots(env)).toEqual(['/tmp/ProgramFiles'])
    expect(getShutUp10Candidates(env)).toEqual([
      '/tmp/ProgramFiles/O&O ShutUp10++/OOSU10.exe',
      '/tmp/ProgramFiles/OO Software/ShutUp10++/OOSU10.exe',
      '/tmp/ProgramFiles/OO Software/O&O ShutUp10++/OOSU10.exe',
      '/tmp/ProgramFiles/OOSU10/OOSU10.exe',
    ])
  })

  it('rejects candidates that escape a resolved root', () => {
    const roots = ['/tmp/ProgramFiles']

    expect(isShutUp10CandidatePathAllowed('/tmp/ProgramFiles/OOSU10/OOSU10.exe', roots)).toBe(true)
    expect(isShutUp10CandidatePathAllowed('/tmp/ProgramFiles/../evil/OOSU10.exe', roots)).toBe(false)
    expect(isShutUp10CandidatePathAllowed('/tmp/Other/OOSU10.exe', roots)).toBe(false)
  })

  it('opens only a resolved candidate under an allowed root', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    process.env.ProgramFiles = '/tmp/ProgramFiles'
    process.env['ProgramFiles(x86)'] = ''
    process.env.LOCALAPPDATA = ''
    mockExistsSync.mockReturnValue(true)
    mockOpenPath.mockResolvedValue('')

    registerUtilityTweaksIpc()
    const result = await invoke('utility-tweaks:shutup10:launch')

    expect(result).toEqual({
      opened: true,
      fallback: false,
      path: '/tmp/ProgramFiles/O&O ShutUp10++/OOSU10.exe',
    })
    expect(mockOpenPath).toHaveBeenCalledWith('/tmp/ProgramFiles/O&O ShutUp10++/OOSU10.exe')
    expect(mockOpenExternal).not.toHaveBeenCalled()
  })

  it('falls back instead of opening from an escaped env root', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    process.env.ProgramFiles = '/tmp/ProgramFiles/..'
    process.env['ProgramFiles(x86)'] = ''
    process.env.LOCALAPPDATA = ''
    mockExistsSync.mockReturnValue(true)
    mockOpenExternal.mockResolvedValue(undefined)

    registerUtilityTweaksIpc()
    const result = await invoke('utility-tweaks:shutup10:launch')

    expect(result).toEqual({
      opened: true,
      fallback: true,
      path: 'https://www.oo-software.com/en/shutup10',
    })
    expect(mockOpenPath).not.toHaveBeenCalled()
    expect(mockOpenExternal).toHaveBeenCalledWith('https://www.oo-software.com/en/shutup10')
  })
})
