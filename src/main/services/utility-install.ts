import { execFile } from 'child_process'
import { promisify } from 'util'
import { isAdmin } from './elevation'
import { psUtf8 } from './exec-utf8'
import { cleanOutput, isValidAppIdForSource, parseWingetListOutput } from './software-updater'
import {
  UTILITY_APP_CATALOG,
  type UtilityCatalogApp,
} from './utility-apps.catalog'
import type {
  UtilityInstallActionResult,
  UtilityInstallProgress,
  UtilityInstalledMap,
  UtilityWingetAction,
} from '../../shared/types'

const execFileAsync = promisify(execFile)

const WINGET_COMMON_ARGS = [
  '--accept-source-agreements',
  '--accept-package-agreements',
  '--disable-interactivity',
  '--silent',
]

const SUCCESS_PATTERNS = [
  'successfully installed',
  'successfully upgraded',
  'successfully uninstalled',
  'installer succeeded',
  'no available upgrade',
  'no newer package versions',
]

const FAILURE_PATTERNS = [
  'installer failed',
  'no package found',
  'no applicable upgrade',
  'no installed package found',
  'installer aborted',
]

const ELEVATION_HINTS = [
  'access is denied',
  'administrator',
  'elevation',
  'requires admin',
  '0x80070005',
]

export function getUtilityAppCatalog(): UtilityCatalogApp[] {
  return UTILITY_APP_CATALOG
}

export async function isWingetAvailable(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    await execFileAsync('winget', ['--version'], {
      timeout: 15_000,
      windowsHide: true,
    })
    return true
  } catch {
    return false
  }
}

/** Map of winget package id → installed version (best effort). */
export async function getInstalledWingetPackages(): Promise<UtilityInstalledMap> {
  const map: UtilityInstalledMap = {}
  if (!(await isWingetAvailable())) return map

  try {
    const result = await execFileAsync(
      'winget',
      ['list', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity'],
      { timeout: 120_000, maxBuffer: 20 * 1024 * 1024, windowsHide: true },
    )
    for (const app of parseWingetListOutput(result.stdout || '')) {
      map[app.id] = { version: app.version, name: app.name }
    }
  } catch (err: any) {
    // winget list can exit non-zero with useful stdout
    if (err?.stdout) {
      for (const app of parseWingetListOutput(String(err.stdout))) {
        map[app.id] = { version: app.version, name: app.name }
      }
    }
  }
  return map
}

async function runWinget(
  args: string[],
): Promise<{ success: boolean; output: string }> {
  let stdout = ''
  try {
    const result = await execFileAsync('winget', args, {
      timeout: 10 * 60 * 1000,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    })
    stdout = result.stdout || ''
  } catch (err: any) {
    if (err?.stdout) stdout = String(err.stdout)
    else return { success: false, output: err?.message || 'Unknown error' }
  }

  const lower = cleanOutput(stdout).toLowerCase()
  const ok = SUCCESS_PATTERNS.some((p) => lower.includes(p))
  const failed = FAILURE_PATTERNS.some((p) => lower.includes(p))
  if (ok && !failed) return { success: true, output: stdout }
  return { success: false, output: stdout }
}

async function runElevatedWinget(args: string[]): Promise<{ success: boolean; output: string }> {
  const joined = args.join(' ')
  const safeArgs = joined.replace(/'/g, "''")
  try {
    const { stdout } = await execFileAsync(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        psUtf8(`$p = Start-Process winget -ArgumentList '${safeArgs}' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`),
      ],
      { timeout: 10 * 60 * 1000, maxBuffer: 10 * 1024 * 1024, windowsHide: true },
    )
    return { success: true, output: stdout || 'Elevated winget completed' }
  } catch (err: any) {
    return { success: false, output: err?.message || 'Elevated winget failed' }
  }
}

async function runWingetAction(
  action: UtilityWingetAction,
  packageId: string,
  alreadyAdmin: boolean,
): Promise<{ success: boolean; error?: string }> {
  if (!isValidAppIdForSource(packageId, 'winget')) {
    return { success: false, error: 'Invalid package ID' }
  }

  const verb =
    action === 'install' ? 'install'
      : action === 'upgrade' ? 'upgrade'
        : 'uninstall'

  const args = [verb, '--id', packageId, '-e', ...WINGET_COMMON_ARGS]
  if (action === 'upgrade') args.push('--include-unknown')

  let result = await runWinget(args)

  if (!result.success && !alreadyAdmin) {
    const lower = cleanOutput(result.output).toLowerCase()
    const needsElevation =
      ELEVATION_HINTS.some((h) => lower.includes(h)) || lower.includes('failed')
    if (needsElevation) {
      result = await runElevatedWinget(args)
    }
  }

  if (result.success) return { success: true }
  const snippet = cleanOutput(result.output).trim().slice(0, 240)
  return { success: false, error: snippet || `${action} failed` }
}

export async function runUtilityInstallActions(
  action: UtilityWingetAction,
  packageIds: string[],
  onProgress?: (data: UtilityInstallProgress) => void,
): Promise<UtilityInstallActionResult> {
  if (process.platform !== 'win32') {
    return { succeeded: 0, failed: packageIds.length, errors: packageIds.map((id) => ({ id, reason: 'Windows only' })) }
  }
  if (!(await isWingetAvailable())) {
    return {
      succeeded: 0,
      failed: packageIds.length,
      errors: packageIds.map((id) => ({ id, reason: 'winget not found — install App Installer from the Microsoft Store' })),
    }
  }

  const unique = [...new Set(packageIds.filter((id) => typeof id === 'string' && id.length > 0))]
  const alreadyAdmin = await isAdmin()
  let succeeded = 0
  let failed = 0
  const errors: UtilityInstallActionResult['errors'] = []

  for (let i = 0; i < unique.length; i++) {
    const id = unique[i]
    onProgress?.({
      phase: 'running',
      action,
      currentId: id,
      current: i + 1,
      total: unique.length,
      message: `${action} ${id}`,
    })
    const result = await runWingetAction(action, id, alreadyAdmin)
    if (result.success) succeeded++
    else {
      failed++
      errors.push({ id, reason: result.error || `${action} failed` })
    }
  }

  onProgress?.({
    phase: 'done',
    action,
    currentId: '',
    current: unique.length,
    total: unique.length,
    message: `Done — ${succeeded} succeeded, ${failed} failed`,
  })

  return { succeeded, failed, errors }
}

/** Upgrade every package that winget reports as upgradeable. */
export async function upgradeAllWingetPackages(
  onProgress?: (data: UtilityInstallProgress) => void,
): Promise<UtilityInstallActionResult> {
  if (process.platform !== 'win32') {
    return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Windows only' }] }
  }
  if (!(await isWingetAvailable())) {
    return {
      succeeded: 0,
      failed: 1,
      errors: [{ id: '*', reason: 'winget not found — install App Installer from the Microsoft Store' }],
    }
  }

  onProgress?.({
    phase: 'running',
    action: 'upgrade',
    currentId: '*',
    current: 0,
    total: 1,
    message: 'Upgrading all winget packages…',
  })

  const alreadyAdmin = await isAdmin()
  const args = ['upgrade', '--all', ...WINGET_COMMON_ARGS, '--include-unknown']
  let result = await runWinget(args)
  if (!result.success && !alreadyAdmin) {
    result = await runElevatedWinget(args)
  }

  onProgress?.({
    phase: 'done',
    action: 'upgrade',
    currentId: '*',
    current: 1,
    total: 1,
    message: result.success ? 'Upgrade all completed' : 'Upgrade all failed',
  })

  if (result.success) return { succeeded: 1, failed: 0, errors: [] }
  return {
    succeeded: 0,
    failed: 1,
    errors: [{ id: '*', reason: cleanOutput(result.output).trim().slice(0, 240) || 'upgrade --all failed' }],
  }
}
