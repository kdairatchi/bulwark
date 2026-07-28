import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const execFileMock = vi.hoisted(() => vi.fn())
const isAdminMock = vi.hoisted(() => vi.fn(() => true))

vi.mock('child_process', () => ({
  execFile: execFileMock,
}))

vi.mock('util', () => ({
  promisify: () => execFileMock,
}))

vi.mock('./elevation', () => ({
  isAdmin: isAdminMock,
}))

const {
  getDailyRegistryBackupCreateCommand,
  getLegacyPanelCommand,
  getOptionalFeatureEnableCommand,
  getOptionalFeatureStatusCommand,
  getUtilityFixCommandSequence,
  runUtilityConfigFix,
  validateUtilityConfigFeatureId,
  validateUtilityConfigFixId,
  validateUtilityLegacyPanelId,
} = await import('./utility-config')

const SHELL_FILES = new Set(['sh', 'bash', 'cmd', 'cmd.exe'])

describe('utility-config helpers', () => {
  const originalPlatform = process.platform

  beforeEach(() => {
    execFileMock.mockReset()
    execFileMock.mockResolvedValue({ stdout: '', stderr: '' })
    isAdminMock.mockReset()
    isAdminMock.mockReturnValue(true)
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
  })

  it('validates IDs strictly against allowlists', () => {
    expect(validateUtilityConfigFeatureId('wsl')).toBe('wsl')
    expect(validateUtilityConfigFeatureId('not-a-feature')).toBeNull()
    expect(validateUtilityConfigFeatureId(['wsl'])).toBeNull()

    expect(validateUtilityLegacyPanelId('network')).toBe('network')
    expect(validateUtilityLegacyPanelId('ncpa.cpl')).toBeNull()
    expect(validateUtilityLegacyPanelId(42)).toBeNull()

    expect(validateUtilityConfigFixId('reset-network')).toBe('reset-network')
    expect(validateUtilityConfigFixId('netsh int ip reset')).toBeNull()
  })

  it('maps legacy panel IDs to fixed execFile commands', () => {
    expect(getLegacyPanelCommand('control-panel')).toEqual({ file: 'control.exe', args: [] })
    expect(getLegacyPanelCommand('network')).toEqual({ file: 'control.exe', args: ['ncpa.cpl'] })
    expect(getLegacyPanelCommand('power')).toEqual({ file: 'control.exe', args: ['powercfg.cpl'] })
    expect(getLegacyPanelCommand('region')).toEqual({ file: 'control.exe', args: ['intl.cpl'] })
    expect(getLegacyPanelCommand('sound')).toEqual({ file: 'control.exe', args: ['mmsys.cpl'] })
    expect(getLegacyPanelCommand('system')).toEqual({ file: 'control.exe', args: ['sysdm.cpl'] })
    expect(getLegacyPanelCommand('user-accounts')).toEqual({
      file: 'control.exe',
      args: ['/name', 'Microsoft.UserAccounts'],
    })
  })

  it('builds optional feature commands through PowerShell execFile specs', () => {
    const status = getOptionalFeatureStatusCommand('wsl')
    const enable = getOptionalFeatureEnableCommand('wsl')

    expect(status?.file).toBe('powershell.exe')
    expect(enable?.file).toBe('powershell.exe')
    expect(status?.args).toContain('-Command')
    expect(enable?.args.join(' ')).toContain('Enable-WindowsOptionalFeature')
    expect(enable?.args.join(' ')).toContain('Microsoft-Windows-Subsystem-Linux')
    expect(enable?.args.join(' ')).toContain('VirtualMachinePlatform')
  })

  it('builds fixed command sequences for fixes without shell executables', () => {
    expect(getUtilityFixCommandSequence('reset-network')).toEqual([
      { file: 'netsh.exe', args: ['int', 'ip', 'reset'] },
      { file: 'netsh.exe', args: ['winsock', 'reset'] },
    ])

    const systemRepair = getUtilityFixCommandSequence('system-corruption-scan')
    expect(systemRepair).toEqual([
      { file: 'sfc.exe', args: ['/scannow'] },
      { file: 'DISM.exe', args: ['/Online', '/Cleanup-Image', '/RestoreHealth'] },
    ])

    for (const id of ['reset-network', 'reset-windows-update', 'system-corruption-scan', 'winget-repair'] as const) {
      for (const command of getUtilityFixCommandSequence(id)) {
        expect(SHELL_FILES.has(command.file.toLowerCase()), `${id}:${command.file}`).toBe(false)
        expect(command.args.every((arg) => typeof arg === 'string')).toBe(true)
      }
    }
  })

  it('builds a documented 12:30 AM registry backup scheduled task command', () => {
    const command = getDailyRegistryBackupCreateCommand()
    expect(command.file).toBe('schtasks.exe')
    expect(command.args).toContain('/Create')
    expect(command.args).toContain('/ST')
    expect(command.args).toContain('00:30')
    expect(command.args).toContain('/RU')
    expect(command.args).toContain('SYSTEM')
    expect(command.args.join(' ')).toContain('RegistryBackup')
    expect(command.args.join(' ')).toContain('reg.exe export HKLM')
  })

  it('invokes config fix progress callback before each command', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    const onProgress = vi.fn()

    const result = await runUtilityConfigFix('system-corruption-scan', onProgress)

    expect(result.success).toBe(true)
    expect(execFileMock).toHaveBeenCalledTimes(2)
    expect(execFileMock.mock.calls[0][0]).toBe('sfc.exe')
    expect(execFileMock.mock.calls[1][0]).toBe('DISM.exe')
    expect(onProgress).toHaveBeenCalledTimes(4)
    expect(onProgress.mock.calls.map(([progress]) => progress.phase)).toEqual([
      'starting',
      'command',
      'command',
      'done',
    ])
    expect(onProgress.mock.calls[1][0]).toMatchObject({
      fixId: 'system-corruption-scan',
      phase: 'command',
      message: 'Running SFC system file scan...',
      current: 1,
      total: 2,
    })
    expect(onProgress.mock.calls[2][0]).toMatchObject({
      fixId: 'system-corruption-scan',
      phase: 'command',
      message: 'Running DISM component store repair...',
      current: 2,
      total: 2,
    })
  })
})
