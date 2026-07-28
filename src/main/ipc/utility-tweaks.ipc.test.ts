import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { join, resolve } from 'node:path'

const handleMap = new Map<string, (...args: unknown[]) => unknown>()
const mockOpenPath = vi.fn()
const mockOpenExternal = vi.fn()
const mockExistsSync = vi.fn()
const mockShowSaveDialog = vi.fn()
const mockShowOpenDialog = vi.fn()
const mockWriteFileSync = vi.fn()
const mockReadFileSync = vi.fn()

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
  dialog: {
    showSaveDialog: (...args: unknown[]) => mockShowSaveDialog(...args),
    showOpenDialog: (...args: unknown[]) => mockShowOpenDialog(...args),
  },
}))

vi.mock('fs', () => ({
  existsSync: (...args: unknown[]) => mockExistsSync(...args),
  writeFileSync: (...args: unknown[]) => mockWriteFileSync(...args),
  readFileSync: (...args: unknown[]) => mockReadFileSync(...args),
}))

vi.mock('../services/utility-tweaks', async () => {
  const actual = await vi.importActual<typeof import('../services/utility-tweaks')>('../services/utility-tweaks')
  return {
    ...actual,
    applyTweaks: vi.fn(),
    getCatalog: vi.fn(() => []),
    getUtilityPowerPlan: vi.fn(),
    revertTweaks: vi.fn(),
    scanTweaks: vi.fn(),
    setUtilityPowerPlan: vi.fn(),
    UTILITY_POWER_PLAN_TARGETS: ['balanced', 'ultimate-performance'],
  }
})

import {
  getResolvedShutUp10Roots,
  getShutUp10Candidates,
  isShutUp10CandidatePathAllowed,
  registerUtilityTweaksIpc,
} from './utility-tweaks.ipc'

const getWindow = () => null

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

    const root = resolve('/tmp/ProgramFiles')
    expect(getResolvedShutUp10Roots(env)).toEqual([root])
    expect(getShutUp10Candidates(env)).toEqual([
      join(root, 'O&O ShutUp10++', 'OOSU10.exe'),
      join(root, 'OO Software', 'ShutUp10++', 'OOSU10.exe'),
      join(root, 'OO Software', 'O&O ShutUp10++', 'OOSU10.exe'),
      join(root, 'OOSU10', 'OOSU10.exe'),
    ])
  })

  it('rejects candidates that escape a resolved root', () => {
    const root = resolve('/tmp/ProgramFiles')
    const roots = [root]

    expect(isShutUp10CandidatePathAllowed(join(root, 'OOSU10', 'OOSU10.exe'), roots)).toBe(true)
    expect(isShutUp10CandidatePathAllowed(`${root}/../evil/OOSU10.exe`, roots)).toBe(false)
    expect(isShutUp10CandidatePathAllowed(resolve('/tmp/Other/OOSU10.exe'), roots)).toBe(false)
  })

  it('opens only a resolved candidate under an allowed root', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    process.env.ProgramFiles = '/tmp/ProgramFiles'
    process.env['ProgramFiles(x86)'] = ''
    process.env.LOCALAPPDATA = ''
    mockExistsSync.mockReturnValue(true)
    mockOpenPath.mockResolvedValue('')

    registerUtilityTweaksIpc(getWindow)
    const result = await invoke('utility-tweaks:shutup10:launch')

    const expectedPath = join(resolve('/tmp/ProgramFiles'), 'O&O ShutUp10++', 'OOSU10.exe')
    expect(result).toEqual({
      opened: true,
      fallback: false,
      path: expectedPath,
    })
    expect(mockOpenPath).toHaveBeenCalledWith(expectedPath)
    expect(mockOpenExternal).not.toHaveBeenCalled()
  })

  it('falls back instead of opening from an escaped env root', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    process.env.ProgramFiles = '/tmp/ProgramFiles/..'
    process.env['ProgramFiles(x86)'] = ''
    process.env.LOCALAPPDATA = ''
    mockExistsSync.mockReturnValue(true)
    mockOpenExternal.mockResolvedValue(undefined)

    registerUtilityTweaksIpc(getWindow)
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

describe('tweak preset export/import IPC', () => {
  beforeEach(() => {
    handleMap.clear()
    vi.clearAllMocks()
    registerUtilityTweaksIpc(getWindow)
  })

  it('exports a JSON preset through the save dialog', async () => {
    mockShowSaveDialog.mockResolvedValue({ canceled: false, filePath: '/tmp/bulwrk-tweaks.json' })

    const path = await invoke('utility-tweaks:export-preset', {
      selected: ['telemetry-level', 'copilot'],
      applied: { 'telemetry-level': true },
    })

    expect(path).toBe('/tmp/bulwrk-tweaks.json')
    expect(mockWriteFileSync).toHaveBeenCalledTimes(1)
    const written = String(mockWriteFileSync.mock.calls[0][1])
    expect(written).toContain('"kind": "bulwrk-utility-tweaks"')
    expect(written).toContain('"telemetry-level"')
    expect(written).toContain('"copilot"')
  })

  it('returns canceled when import dialog is dismissed', async () => {
    mockShowOpenDialog.mockResolvedValue({ canceled: true, filePaths: [] })
    await expect(invoke('utility-tweaks:import-preset')).resolves.toEqual({
      ok: false,
      reason: 'canceled',
    })
  })

  it('imports known IDs and skips unknowns', async () => {
    mockShowOpenDialog.mockResolvedValue({ canceled: false, filePaths: ['/tmp/import.json'] })
    mockReadFileSync.mockReturnValue(JSON.stringify({
      version: 1,
      kind: 'bulwrk-utility-tweaks',
      selected: ['telemetry-level', 'not-real', 'copilot'],
    }))

    await expect(invoke('utility-tweaks:import-preset')).resolves.toEqual({
      ok: true,
      selected: ['telemetry-level', 'copilot'],
      skipped: 1,
      path: '/tmp/import.json',
    })
  })

  it('rejects invalid preset files', async () => {
    mockShowOpenDialog.mockResolvedValue({ canceled: false, filePaths: ['/tmp/bad.json'] })
    mockReadFileSync.mockReturnValue('{"kind":"wrong"}')

    await expect(invoke('utility-tweaks:import-preset')).resolves.toEqual({
      ok: false,
      reason: 'invalid',
    })
  })
})
