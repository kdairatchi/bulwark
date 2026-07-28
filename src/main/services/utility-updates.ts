import { execFile } from 'child_process'
import { promisify } from 'util'
import { isAdmin } from './elevation'
import { psUtf8 } from './exec-utf8'
import { getPlatform } from '../platform'
import { runUtilityConfigFix } from './utility-config'
import type {
  UtilityOsUpdateCheckResult,
  UtilityOsUpdateInfo,
  UtilityOsUpdateInstallResult,
  UtilityUpdatesHelperId,
  UtilityUpdatesHelperResult,
  UtilityUpdatesPauseDays,
  UtilityUpdatesPauseResult,
  UtilityUpdatesResumeResult,
  UtilityUpdatesStatus,
} from '../../shared/types'

const execFileAsync = promisify(execFile)

export const UTILITY_UPDATE_PAUSE_DAYS = [1, 7, 14, 35] as const
export const UTILITY_UPDATE_HELPER_IDS = ['open-wu-settings', 'reset-wu-services', 'winget-repair'] as const

const WU_UX_SETTINGS_PATH = 'HKLM:\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings'
const PAUSE_EXPIRY_PROPERTY = 'PauseUpdatesExpiryTime'
const PAUSE_VALUE_NAMES = [
  'PauseUpdatesExpiryTime',
  'PauseFeatureUpdatesStartTime',
  'PauseFeatureUpdatesEndTime',
  'PauseQualityUpdatesStartTime',
  'PauseQualityUpdatesEndTime',
] as const

export interface UtilityCommandSpec {
  file: string
  args: string[]
}

const COMMAND_OPTS = {
  timeout: 5 * 60 * 1000,
  maxBuffer: 10 * 1024 * 1024,
  windowsHide: true,
}

const pauseDaysSet = new Set<number>(UTILITY_UPDATE_PAUSE_DAYS)
const helperIdsSet = new Set<string>(UTILITY_UPDATE_HELPER_IDS)

export function validateUtilityUpdatesPauseDays(days: unknown): UtilityUpdatesPauseDays | null {
  if (typeof days !== 'number' || !Number.isInteger(days)) return null
  return pauseDaysSet.has(days) ? (days as UtilityUpdatesPauseDays) : null
}

export function validateUtilityUpdatesHelperId(id: unknown): UtilityUpdatesHelperId | null {
  return typeof id === 'string' && helperIdsSet.has(id)
    ? (id as UtilityUpdatesHelperId)
    : null
}

export function getPauseExpiryStatusCommand(): UtilityCommandSpec {
  return powershellCommand(pauseExpiryStatusScript())
}

export function getPauseUpdatesCommand(days: UtilityUpdatesPauseDays): UtilityCommandSpec {
  return powershellCommand(pauseUpdatesScript(days))
}

export function getResumeUpdatesCommand(): UtilityCommandSpec {
  return powershellCommand(resumeUpdatesScript())
}

export function getOpenWuSettingsCommand(): UtilityCommandSpec {
  return { file: 'explorer.exe', args: ['ms-settings:windowsupdate'] }
}

export async function getUtilityUpdatesStatus(): Promise<UtilityUpdatesStatus> {
  if (process.platform !== 'win32') {
    return {
      available: false,
      isAdmin: false,
      paused: false,
      pauseExpiresAt: null,
      details: 'Windows only',
    }
  }

  const admin = isAdmin()
  try {
    const { stdout } = await runCommand(getPauseExpiryStatusCommand(), {
      ...COMMAND_OPTS,
      timeout: 30_000,
    })
    const raw = stdout.trim()
    if (!raw) {
      return {
        available: true,
        isAdmin: admin,
        paused: false,
        pauseExpiresAt: null,
        details: 'Windows Update pause is not active.',
      }
    }

    const expiry = parsePauseExpiry(raw)
    if (expiry && expiry.getTime() > Date.now()) {
      const iso = expiry.toISOString()
      return {
        available: true,
        isAdmin: admin,
        paused: true,
        pauseExpiresAt: iso,
        details: `Windows Update paused until ${iso}.`,
      }
    }

    return {
      available: true,
      isAdmin: admin,
      paused: false,
      pauseExpiresAt: raw || null,
      details: raw
        ? 'Pause expiry is set but not in the future.'
        : 'Windows Update pause is not active.',
    }
  } catch (err) {
    return {
      available: true,
      isAdmin: admin,
      paused: false,
      pauseExpiresAt: null,
      details: errorMessage(err),
    }
  }
}

export async function checkUtilityOsUpdates(): Promise<UtilityOsUpdateCheckResult> {
  if (process.platform !== 'win32') {
    return { available: false, updates: [], error: 'Windows only' }
  }

  try {
    const updates = await getPlatform().commands.checkOsUpdates()
    if (updates === null) {
      return { available: false, updates: [], error: 'Not supported on this platform' }
    }
    return {
      available: true,
      updates: updates.map(toUtilityOsUpdateInfo),
    }
  } catch (err) {
    return { available: false, updates: [], error: errorMessage(err) }
  }
}

export async function installUtilityOsUpdates(): Promise<UtilityOsUpdateInstallResult> {
  if (process.platform !== 'win32') {
    return {
      success: false,
      installed: 0,
      needsReboot: false,
      resultCode: -1,
      needsAdmin: false,
      error: 'Windows only',
    }
  }

  if (!isAdmin()) {
    return {
      success: false,
      installed: 0,
      needsReboot: false,
      resultCode: -1,
      needsAdmin: true,
      error: 'Administrator privileges required',
    }
  }

  try {
    const result = await getPlatform().commands.installOsUpdates()
    if (result === null) {
      return {
        success: false,
        installed: 0,
        needsReboot: false,
        resultCode: -1,
        needsAdmin: false,
        error: 'Not supported on this platform',
      }
    }

    const success = result.installed >= 0 && (result.resultCode === 0 || result.resultCode === 2)
    return {
      success,
      installed: result.installed,
      needsReboot: result.needsReboot,
      resultCode: result.resultCode,
      needsAdmin: false,
      ...(success ? {} : { error: `Install finished with result code ${result.resultCode}` }),
    }
  } catch (err) {
    return {
      success: false,
      installed: 0,
      needsReboot: false,
      resultCode: -1,
      needsAdmin: false,
      error: errorMessage(err),
    }
  }
}

export async function pauseUtilityUpdates(
  days: UtilityUpdatesPauseDays,
): Promise<UtilityUpdatesPauseResult> {
  if (process.platform !== 'win32') {
    return { success: false, needsAdmin: false, error: 'Windows only' }
  }
  if (!isAdmin()) {
    return { success: false, needsAdmin: true, error: 'Administrator privileges required' }
  }

  try {
    await runCommand(getPauseUpdatesCommand(days), COMMAND_OPTS)
    const status = await getUtilityUpdatesStatus()
    return { success: true, status, needsAdmin: false }
  } catch (err) {
    return { success: false, needsAdmin: false, error: errorMessage(err) }
  }
}

export async function resumeUtilityUpdates(): Promise<UtilityUpdatesResumeResult> {
  if (process.platform !== 'win32') {
    return { success: false, needsAdmin: false, error: 'Windows only' }
  }
  if (!isAdmin()) {
    return { success: false, needsAdmin: true, error: 'Administrator privileges required' }
  }

  try {
    await runCommand(getResumeUpdatesCommand(), COMMAND_OPTS)
    const status = await getUtilityUpdatesStatus()
    return { success: true, status, needsAdmin: false }
  } catch (err) {
    return { success: false, needsAdmin: false, error: errorMessage(err) }
  }
}

export async function runUtilityUpdatesHelper(
  id: UtilityUpdatesHelperId,
): Promise<UtilityUpdatesHelperResult> {
  if (process.platform !== 'win32') {
    return helperError(id, 'Windows only')
  }

  switch (id) {
    case 'open-wu-settings': {
      try {
        const command = getOpenWuSettingsCommand()
        await execFileAsync(command.file, command.args, {
          timeout: 15_000,
          maxBuffer: 1024 * 1024,
          windowsHide: true,
        })
        return {
          id,
          success: true,
          summary: 'Opened Windows Update settings.',
          needsAdmin: false,
          requiresReboot: false,
        }
      } catch (err) {
        return helperError(id, errorMessage(err))
      }
    }
    case 'reset-wu-services': {
      const result = await runUtilityConfigFix('reset-windows-update')
      return mapConfigFixResult(id, result)
    }
    case 'winget-repair': {
      const result = await runUtilityConfigFix('winget-repair')
      return mapConfigFixResult(id, result)
    }
  }
}

function pauseExpiryStatusScript(): string {
  return `
    $path = '${WU_UX_SETTINGS_PATH}'
    try {
      $val = (Get-ItemProperty -Path $path -Name '${PAUSE_EXPIRY_PROPERTY}' -ErrorAction Stop).${PAUSE_EXPIRY_PROPERTY}
      if ($null -eq $val) { Write-Output '' } else { Write-Output ([string]$val) }
    } catch {
      Write-Output ''
    }
  `
}

function pauseUpdatesScript(days: UtilityUpdatesPauseDays): string {
  // days is validated against UTILITY_UPDATE_PAUSE_DAYS before reaching here;
  // interpolate only as a numeric literal — never free-form user input.
  return `
    $path = '${WU_UX_SETTINGS_PATH}'
    $start = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $end = (Get-Date).AddDays(${days}).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name 'PauseUpdatesExpiryTime' -Value $end
    Set-ItemProperty -Path $path -Name 'PauseFeatureUpdatesStartTime' -Value $start
    Set-ItemProperty -Path $path -Name 'PauseFeatureUpdatesEndTime' -Value $end
    Set-ItemProperty -Path $path -Name 'PauseQualityUpdatesStartTime' -Value $start
    Set-ItemProperty -Path $path -Name 'PauseQualityUpdatesEndTime' -Value $end
    Write-Output $end
  `
}

function resumeUpdatesScript(): string {
  const names = PAUSE_VALUE_NAMES.map((name) => `'${name}'`).join(',')
  return `
    $path = '${WU_UX_SETTINGS_PATH}'
    $names = @(${names})
    if (Test-Path $path) {
      foreach ($name in $names) {
        Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
      }
    }
    Write-Output 'resumed'
  `
}

function powershellCommand(script: string): UtilityCommandSpec {
  return {
    file: 'powershell.exe',
    args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psUtf8(script)],
  }
}

async function runCommand(
  command: UtilityCommandSpec,
  opts: typeof COMMAND_OPTS = COMMAND_OPTS,
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(command.file, command.args, opts) as Promise<{ stdout: string; stderr: string }>
}

function parsePauseExpiry(raw: string): Date | null {
  const trimmed = raw.trim()
  if (!trimmed) return null
  const date = new Date(trimmed)
  if (Number.isNaN(date.getTime())) return null
  return date
}

function toUtilityOsUpdateInfo(update: {
  title: string
  kb: string
  severity: string
  sizeBytes: number
  downloaded: boolean
}): UtilityOsUpdateInfo {
  return {
    title: update.title,
    kb: update.kb,
    severity: update.severity,
    sizeBytes: update.sizeBytes,
    downloaded: update.downloaded,
  }
}

function mapConfigFixResult(
  id: UtilityUpdatesHelperId,
  result: {
    id: string
    success: boolean
    summary: string
    needsAdmin: boolean
    requiresReboot: boolean
    log?: string
    error?: string
  },
): UtilityUpdatesHelperResult {
  return {
    id,
    success: result.success,
    summary: result.summary,
    needsAdmin: result.needsAdmin,
    requiresReboot: result.requiresReboot,
    log: result.log,
    error: result.error,
  }
}

function helperError(id: string, summary: string): UtilityUpdatesHelperResult {
  return {
    id,
    success: false,
    summary,
    error: summary,
    needsAdmin: false,
    requiresReboot: false,
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
