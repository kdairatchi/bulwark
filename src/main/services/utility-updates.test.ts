import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const execFileMock = vi.hoisted(() => vi.fn())
const isAdminMock = vi.hoisted(() => vi.fn(() => true))
const checkOsUpdatesMock = vi.hoisted(() => vi.fn())
const installOsUpdatesMock = vi.hoisted(() => vi.fn())
const runUtilityConfigFixMock = vi.hoisted(() => vi.fn())

vi.mock('child_process', () => ({
  execFile: execFileMock,
}))

vi.mock('util', () => ({
  promisify: () => execFileMock,
}))

vi.mock('./elevation', () => ({
  isAdmin: isAdminMock,
}))

vi.mock('../platform', () => ({
  getPlatform: () => ({
    commands: {
      checkOsUpdates: checkOsUpdatesMock,
      installOsUpdates: installOsUpdatesMock,
    },
  }),
}))

vi.mock('./utility-config', () => ({
  runUtilityConfigFix: (...args: unknown[]) => runUtilityConfigFixMock(...args),
}))

const {
  getOpenWuSettingsCommand,
  getPauseExpiryStatusCommand,
  getPauseUpdatesCommand,
  getResumeUpdatesCommand,
  getUtilityUpdatesStatus,
  installUtilityOsUpdates,
  pauseUtilityUpdates,
  resumeUtilityUpdates,
  runUtilityUpdatesHelper,
  UTILITY_UPDATE_HELPER_IDS,
  UTILITY_UPDATE_PAUSE_DAYS,
  validateUtilityUpdatesHelperId,
  validateUtilityUpdatesPauseDays,
} = await import('./utility-updates')

describe('utility-updates', () => {
  const originalPlatform = process.platform

  beforeEach(() => {
    execFileMock.mockReset()
    execFileMock.mockResolvedValue({ stdout: '', stderr: '' })
    isAdminMock.mockReset()
    isAdminMock.mockReturnValue(true)
    checkOsUpdatesMock.mockReset()
    installOsUpdatesMock.mockReset()
    runUtilityConfigFixMock.mockReset()
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
  })

  it('validates pause days against the allowlist', () => {
    expect(UTILITY_UPDATE_PAUSE_DAYS).toEqual([1, 7, 14, 35])
    expect(validateUtilityUpdatesPauseDays(1)).toBe(1)
    expect(validateUtilityUpdatesPauseDays(7)).toBe(7)
    expect(validateUtilityUpdatesPauseDays(14)).toBe(14)
    expect(validateUtilityUpdatesPauseDays(35)).toBe(35)
    expect(validateUtilityUpdatesPauseDays(3)).toBeNull()
    expect(validateUtilityUpdatesPauseDays(0)).toBeNull()
    expect(validateUtilityUpdatesPauseDays('7')).toBeNull()
    expect(validateUtilityUpdatesPauseDays(7.5)).toBeNull()
    expect(validateUtilityUpdatesPauseDays(null)).toBeNull()
  })

  it('validates helper IDs against the allowlist', () => {
    expect(UTILITY_UPDATE_HELPER_IDS).toEqual([
      'open-wu-settings',
      'reset-wu-services',
      'winget-repair',
    ])
    expect(validateUtilityUpdatesHelperId('open-wu-settings')).toBe('open-wu-settings')
    expect(validateUtilityUpdatesHelperId('reset-wu-services')).toBe('reset-wu-services')
    expect(validateUtilityUpdatesHelperId('winget-repair')).toBe('winget-repair')
    expect(validateUtilityUpdatesHelperId('reset-windows-update')).toBeNull()
    expect(validateUtilityUpdatesHelperId(42)).toBeNull()
  })

  it('builds pause/resume PowerShell specs against the fixed UX Settings path', () => {
    const status = getPauseExpiryStatusCommand()
    expect(status.file).toBe('powershell.exe')
    expect(status.args.join(' ')).toContain('HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings')
    expect(status.args.join(' ')).toContain('PauseUpdatesExpiryTime')

    const pause = getPauseUpdatesCommand(7)
    expect(pause.file).toBe('powershell.exe')
    expect(pause.args.join(' ')).toContain('AddDays(7)')
    expect(pause.args.join(' ')).toContain('PauseFeatureUpdatesStartTime')
    expect(pause.args.join(' ')).toContain('PauseQualityUpdatesEndTime')
    expect(pause.args.join(' ')).not.toContain('SoftwareDistribution')

    const resume = getResumeUpdatesCommand()
    expect(resume.file).toBe('powershell.exe')
    for (const name of [
      'PauseUpdatesExpiryTime',
      'PauseFeatureUpdatesStartTime',
      'PauseFeatureUpdatesEndTime',
      'PauseQualityUpdatesStartTime',
      'PauseQualityUpdatesEndTime',
    ]) {
      expect(resume.args.join(' ')).toContain(name)
    }
    expect(resume.args.join(' ')).toContain('Remove-ItemProperty')
  })

  it('exports open Windows Update settings as explorer.exe + ms-settings URI', () => {
    expect(getOpenWuSettingsCommand()).toEqual({
      file: 'explorer.exe',
      args: ['ms-settings:windowsupdate'],
    })
  })

  it('reports unavailable status on non-win32', async () => {
    Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
    const status = await getUtilityUpdatesStatus()
    expect(status).toEqual({
      available: false,
      isAdmin: false,
      paused: false,
      pauseExpiresAt: null,
      details: 'Windows only',
    })
    expect(execFileMock).not.toHaveBeenCalled()
  })

  it('parses a future pause expiry as paused', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    const future = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    execFileMock.mockResolvedValue({ stdout: `${future}\n`, stderr: '' })

    const status = await getUtilityUpdatesStatus()
    expect(status.available).toBe(true)
    expect(status.paused).toBe(true)
    expect(status.pauseExpiresAt).toBe(new Date(future).toISOString())
    expect(status.isAdmin).toBe(true)
  })

  it('gates install/pause/resume behind admin on win32', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    isAdminMock.mockReturnValue(false)

    await expect(installUtilityOsUpdates()).resolves.toMatchObject({
      success: false,
      needsAdmin: true,
      installed: 0,
    })
    expect(installOsUpdatesMock).not.toHaveBeenCalled()

    await expect(pauseUtilityUpdates(7)).resolves.toEqual({
      success: false,
      needsAdmin: true,
      error: 'Administrator privileges required',
    })
    expect(execFileMock).not.toHaveBeenCalled()

    await expect(resumeUtilityUpdates()).resolves.toEqual({
      success: false,
      needsAdmin: true,
      error: 'Administrator privileges required',
    })
    expect(execFileMock).not.toHaveBeenCalled()
  })

  it('opens Windows Update settings via the fixed explorer command', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    const result = await runUtilityUpdatesHelper('open-wu-settings')
    expect(result.success).toBe(true)
    expect(execFileMock).toHaveBeenCalledWith(
      'explorer.exe',
      ['ms-settings:windowsupdate'],
      expect.objectContaining({ windowsHide: true }),
    )
  })

  it('delegates reset-wu-services and winget-repair to config fixes', async () => {
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    runUtilityConfigFixMock.mockResolvedValueOnce({
      id: 'reset-windows-update',
      success: true,
      summary: 'done',
      needsAdmin: false,
      requiresReboot: true,
    })
    runUtilityConfigFixMock.mockResolvedValueOnce({
      id: 'winget-repair',
      success: true,
      summary: 'repaired',
      needsAdmin: false,
      requiresReboot: false,
    })

    const reset = await runUtilityUpdatesHelper('reset-wu-services')
    expect(runUtilityConfigFixMock).toHaveBeenCalledWith('reset-windows-update')
    expect(reset).toMatchObject({
      id: 'reset-wu-services',
      success: true,
      requiresReboot: true,
    })

    const repair = await runUtilityUpdatesHelper('winget-repair')
    expect(runUtilityConfigFixMock).toHaveBeenCalledWith('winget-repair')
    expect(repair).toMatchObject({ id: 'winget-repair', success: true })
  })
})
