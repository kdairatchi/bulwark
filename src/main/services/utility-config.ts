import { execFile } from 'child_process'
import { promisify } from 'util'
import { isAdmin } from './elevation'
import { psUtf8 } from './exec-utf8'
import {
  DAILY_REGISTRY_BACKUP_TASK,
  OPENSSH_SERVER_CAPABILITY,
  UTILITY_CONFIG_FEATURES,
  UTILITY_CONFIG_FIXES,
  UTILITY_LEGACY_PANELS,
  type UtilityConfigFeatureDefinition,
  type UtilityConfigFeatureId,
  type UtilityConfigFixDefinition,
  type UtilityConfigFixId,
  type UtilityLegacyPanelDefinition,
  type UtilityLegacyPanelId,
} from './utility-config.catalog'
import type {
  UtilityConfigActionResult,
  UtilityConfigCatalogResult,
  UtilityConfigFeatureStatusResult,
  UtilityConfigFixMetadata,
  UtilityConfigOpenSshStatusResult,
  UtilityLegacyPanelLaunchResult,
} from '../../shared/types'

const execFileAsync = promisify(execFile)

export interface UtilityCommandSpec {
  file: string
  args: string[]
}

const COMMAND_OPTS = {
  timeout: 5 * 60 * 1000,
  maxBuffer: 10 * 1024 * 1024,
  windowsHide: true,
}

const LONG_COMMAND_OPTS = {
  timeout: 45 * 60 * 1000,
  maxBuffer: 20 * 1024 * 1024,
  windowsHide: true,
}

const featureIds = new Set(UTILITY_CONFIG_FEATURES.map((feature) => feature.id))
const panelIds = new Set(UTILITY_LEGACY_PANELS.map((panel) => panel.id))
const fixIds = new Set(UTILITY_CONFIG_FIXES.map((fix) => fix.id))

export function getUtilityConfigCatalog(): UtilityConfigCatalogResult {
  if (process.platform !== 'win32') {
    return { available: false, features: [], legacyPanels: [], fixes: [], openSsh: null }
  }

  return {
    available: true,
    features: UTILITY_CONFIG_FEATURES.map(({ id, name, description, kind, requiresAdmin, notes }) => ({
      id,
      name,
      description,
      kind,
      requiresAdmin,
      notes,
    })),
    legacyPanels: UTILITY_LEGACY_PANELS.map(({ id, name, description }) => ({ id, name, description })),
    fixes: UTILITY_CONFIG_FIXES.map(toFixMetadata),
    openSsh: {
      id: 'openssh-server',
      name: 'OpenSSH Server',
      description: 'Install the Windows OpenSSH Server capability and start sshd.',
      requiresAdmin: true,
      capabilityName: OPENSSH_SERVER_CAPABILITY,
    },
  }
}

export function validateUtilityConfigFeatureId(id: unknown): UtilityConfigFeatureId | null {
  return typeof id === 'string' && featureIds.has(id as UtilityConfigFeatureId)
    ? id as UtilityConfigFeatureId
    : null
}

export function validateUtilityLegacyPanelId(id: unknown): UtilityLegacyPanelId | null {
  return typeof id === 'string' && panelIds.has(id as UtilityLegacyPanelId)
    ? id as UtilityLegacyPanelId
    : null
}

export function validateUtilityConfigFixId(id: unknown): UtilityConfigFixId | null {
  return typeof id === 'string' && fixIds.has(id as UtilityConfigFixId)
    ? id as UtilityConfigFixId
    : null
}

export function getOptionalFeatureStatusCommand(id: UtilityConfigFeatureId): UtilityCommandSpec | null {
  const feature = findFeature(id)
  if (!feature?.featureNames?.length) return null
  return powershellCommand(optionalFeatureStatusScript(feature.featureNames))
}

export function getOptionalFeatureEnableCommand(id: UtilityConfigFeatureId): UtilityCommandSpec | null {
  const feature = findFeature(id)
  if (!feature?.featureNames?.length) return null
  return powershellCommand(optionalFeatureEnableScript(feature.featureNames))
}

export function getLegacyPanelCommand(id: UtilityLegacyPanelId): UtilityCommandSpec {
  const panel = findPanel(id)
  if (!panel) throw new Error('Unknown legacy panel ID')
  return { file: panel.command, args: [...panel.args] }
}

export function getUtilityFixCommandSequence(id: UtilityConfigFixId): UtilityCommandSpec[] {
  switch (id) {
    case 'reset-network':
      return [
        { file: 'netsh.exe', args: ['int', 'ip', 'reset'] },
        { file: 'netsh.exe', args: ['winsock', 'reset'] },
      ]
    case 'reset-windows-update':
      return [powershellCommand(windowsUpdateRestartScript())]
    case 'system-corruption-scan':
      return [
        { file: 'sfc.exe', args: ['/scannow'] },
        { file: 'DISM.exe', args: ['/Online', '/Cleanup-Image', '/RestoreHealth'] },
      ]
    case 'winget-repair':
      return [
        { file: 'winget.exe', args: ['source', 'reset', '--force'] },
        { file: 'winget.exe', args: ['source', 'update'] },
      ]
  }
}

export function getDailyRegistryBackupCreateCommand(): UtilityCommandSpec {
  return {
    file: 'schtasks.exe',
    args: [
      '/Create',
      '/TN',
      DAILY_REGISTRY_BACKUP_TASK,
      '/SC',
      'DAILY',
      '/ST',
      '00:30',
      '/RL',
      'HIGHEST',
      '/RU',
      'SYSTEM',
      '/TR',
      dailyRegistryBackupTaskAction(),
      '/F',
    ],
  }
}

export async function getUtilityConfigFeatureStatus(
  id: UtilityConfigFeatureId,
): Promise<UtilityConfigFeatureStatusResult> {
  const feature = findFeature(id)
  if (!feature) return unavailableFeatureStatus(String(id), 'Unknown feature ID')
  if (process.platform !== 'win32') return unavailableFeatureStatus(id, 'Windows only')

  try {
    if (feature.kind === 'optional-feature') return getOptionalFeatureStatus(feature)
    if (feature.id === 'f8-boot-recovery') return getF8BootRecoveryStatus()
    if (feature.id === 'daily-registry-backup') return getDailyRegistryBackupStatus()
    return unavailableFeatureStatus(id, 'Unsupported feature kind')
  } catch (err) {
    return {
      id,
      available: false,
      enabled: null,
      status: 'unknown',
      details: errorMessage(err),
    }
  }
}

export async function enableUtilityConfigFeature(
  id: UtilityConfigFeatureId,
): Promise<UtilityConfigActionResult> {
  const feature = findFeature(id)
  if (!feature) return actionError(String(id), 'Unknown feature ID')
  if (process.platform !== 'win32') return actionError(id, 'Windows only')
  if (feature.requiresAdmin && !isAdmin()) return needsAdminResult(id)

  try {
    if (feature.kind === 'optional-feature') return enableOptionalFeature(feature)
    if (feature.id === 'f8-boot-recovery') {
      const result = await runCommand({ file: 'bcdedit.exe', args: ['/set', '{default}', 'bootmenupolicy', 'legacy'] })
      return {
        id,
        success: true,
        summary: 'Legacy F8 boot recovery is enabled.',
        log: result.stdout + result.stderr,
        requiresReboot: false,
        needsAdmin: false,
      }
    }
    if (feature.id === 'daily-registry-backup') {
      const result = await runCommand(getDailyRegistryBackupCreateCommand())
      return {
        id,
        success: true,
        summary: 'Daily registry backup task is scheduled for 12:30 AM.',
        log: result.stdout + result.stderr,
        requiresReboot: false,
        needsAdmin: false,
      }
    }
    return actionError(id, 'Unsupported feature kind')
  } catch (err) {
    return actionError(id, errorMessage(err))
  }
}

export async function revertUtilityConfigFeature(
  id: UtilityConfigFeatureId,
): Promise<UtilityConfigActionResult> {
  const feature = findFeature(id)
  if (!feature) return actionError(String(id), 'Unknown feature ID')
  if (process.platform !== 'win32') return actionError(id, 'Windows only')
  if (feature.requiresAdmin && !isAdmin()) return needsAdminResult(id)

  try {
    if (feature.id === 'f8-boot-recovery') {
      const result = await runCommand({ file: 'bcdedit.exe', args: ['/set', '{default}', 'bootmenupolicy', 'standard'] })
      return {
        id,
        success: true,
        summary: 'Boot menu policy reverted to standard.',
        log: result.stdout + result.stderr,
        requiresReboot: false,
        needsAdmin: false,
      }
    }
    if (feature.id === 'daily-registry-backup') {
      const result = await runCommand({ file: 'schtasks.exe', args: ['/Delete', '/TN', DAILY_REGISTRY_BACKUP_TASK, '/F'] })
      return {
        id,
        success: true,
        summary: 'Daily registry backup task removed.',
        log: result.stdout + result.stderr,
        requiresReboot: false,
        needsAdmin: false,
      }
    }
    return actionError(id, 'This feature does not have a safe revert action.')
  } catch (err) {
    return actionError(id, errorMessage(err))
  }
}

export async function launchUtilityLegacyPanel(
  id: UtilityLegacyPanelId,
): Promise<UtilityLegacyPanelLaunchResult> {
  if (process.platform !== 'win32') return { id, launched: false, error: 'Windows only' }

  try {
    const command = getLegacyPanelCommand(id)
    await runCommand(command, { timeout: 10_000, maxBuffer: 1024 * 1024, windowsHide: true })
    return { id, launched: true }
  } catch (err) {
    if (id === 'user-accounts') {
      try {
        await runCommand({ file: 'netplwiz.exe', args: [] }, { timeout: 10_000, maxBuffer: 1024 * 1024, windowsHide: true })
        return { id, launched: true }
      } catch {
        // Preserve the original Control Panel error below.
      }
    }
    return { id, launched: false, error: errorMessage(err) }
  }
}

export async function getOpenSshStatus(): Promise<UtilityConfigOpenSshStatusResult> {
  if (process.platform !== 'win32') {
    return {
      available: false,
      installed: false,
      serviceRunning: false,
      startupType: null,
      details: 'Windows only',
    }
  }

  try {
    const result = await runCommand(powershellCommand(openSshStatusScript()), { ...COMMAND_OPTS, timeout: 30_000 })
    return parseOpenSshStatus(result.stdout)
  } catch (err) {
    return {
      available: false,
      installed: false,
      serviceRunning: false,
      startupType: null,
      details: errorMessage(err),
    }
  }
}

export async function enableOpenSshServer(): Promise<UtilityConfigActionResult> {
  if (process.platform !== 'win32') return actionError('openssh-server', 'Windows only')
  if (!isAdmin()) return needsAdminResult('openssh-server')

  try {
    const result = await runCommand(powershellCommand(openSshEnableScript()))
    return {
      id: 'openssh-server',
      success: true,
      summary: 'OpenSSH Server is installed and sshd has been started when possible.',
      log: result.stdout + result.stderr,
      requiresReboot: false,
      needsAdmin: false,
    }
  } catch (err) {
    return actionError('openssh-server', errorMessage(err))
  }
}

export async function runUtilityConfigFix(
  id: UtilityConfigFixId,
): Promise<UtilityConfigActionResult> {
  const fix = findFix(id)
  if (!fix) return actionError(String(id), 'Unknown fix ID')
  if (process.platform !== 'win32') return actionError(id, 'Windows only')
  if (fix.requiresAdmin && !isAdmin()) return needsAdminResult(id)

  try {
    if (id === 'winget-repair') {
      try {
        await runCommand({ file: 'winget.exe', args: ['--version'] }, { timeout: 15_000, maxBuffer: 1024 * 1024, windowsHide: true })
      } catch {
        return actionError(id, 'winget not found - install or repair App Installer from the Microsoft Store.')
      }
    }

    const logs: string[] = []
    const opts = id === 'system-corruption-scan' ? LONG_COMMAND_OPTS : COMMAND_OPTS
    for (const command of getUtilityFixCommandSequence(id)) {
      const result = await runCommand(command, opts)
      logs.push(`> ${command.file} ${command.args.join(' ')}\n${result.stdout}${result.stderr}`)
    }

    return {
      id,
      success: true,
      summary: fixSummary(fix),
      log: logs.join('\n'),
      requiresReboot: fix.requiresReboot,
      needsAdmin: false,
    }
  } catch (err) {
    return actionError(id, errorMessage(err))
  }
}

function toFixMetadata(fix: UtilityConfigFixDefinition): UtilityConfigFixMetadata {
  return {
    id: fix.id,
    name: fix.name,
    description: fix.description,
    requiresAdmin: fix.requiresAdmin,
    requiresReboot: fix.requiresReboot,
    notes: fix.notes,
  }
}

async function getOptionalFeatureStatus(
  feature: UtilityConfigFeatureDefinition,
): Promise<UtilityConfigFeatureStatusResult> {
  const command = getOptionalFeatureStatusCommand(feature.id)
  if (!command) return unavailableFeatureStatus(feature.id, 'Feature has no optional feature names')

  const result = await runCommand(command, { ...COMMAND_OPTS, timeout: 30_000 })
  const entries = parseOptionalFeatureLines(result.stdout)
  const available = entries.filter((entry) => entry.state !== 'Unavailable')

  if (available.length === 0) {
    return {
      id: feature.id,
      available: false,
      enabled: false,
      status: 'unavailable',
      details: 'No matching Windows optional features are available on this edition.',
      log: result.stdout + result.stderr,
    }
  }

  const enabledCount = available.filter((entry) => entry.state === 'Enabled').length
  const status = enabledCount === available.length
    ? 'enabled'
    : enabledCount > 0
      ? 'partial'
      : 'disabled'

  return {
    id: feature.id,
    available: true,
    enabled: status === 'enabled',
    status,
    details: available.map((entry) => `${entry.name}: ${entry.state}`).join(', '),
    log: result.stdout + result.stderr,
  }
}

async function enableOptionalFeature(
  feature: UtilityConfigFeatureDefinition,
): Promise<UtilityConfigActionResult> {
  const command = getOptionalFeatureEnableCommand(feature.id)
  if (!command) return actionError(feature.id, 'Feature has no optional feature names')

  const result = await runCommand(command)
  const parsed = parseActionLines(result.stdout)
  const succeeded = parsed.filter((entry) => entry.ok)
  const failed = parsed.filter((entry) => !entry.ok)

  if (succeeded.length === 0) {
    return actionError(feature.id, failed.map((entry) => `${entry.id}: ${entry.message}`).join('; ') || 'No feature was enabled')
  }

  const warning = failed.length > 0
    ? ` Some feature names were unavailable or failed: ${failed.map((entry) => entry.id).join(', ')}.`
    : ''

  return {
    id: feature.id,
    success: true,
    summary: `${feature.name} enable command completed.${warning}`,
    log: result.stdout + result.stderr,
    requiresReboot: true,
    needsAdmin: false,
  }
}

async function getF8BootRecoveryStatus(): Promise<UtilityConfigFeatureStatusResult> {
  const result = await runCommand({ file: 'bcdedit.exe', args: ['/enum', '{default}'] }, { ...COMMAND_OPTS, timeout: 30_000 })
  const legacy = /bootmenupolicy\s+legacy/i.test(result.stdout)
  return {
    id: 'f8-boot-recovery',
    available: true,
    enabled: legacy,
    status: legacy ? 'enabled' : 'disabled',
    details: legacy ? 'bootmenupolicy is legacy' : 'bootmenupolicy is standard or not set',
    log: result.stdout + result.stderr,
  }
}

async function getDailyRegistryBackupStatus(): Promise<UtilityConfigFeatureStatusResult> {
  try {
    const result = await runCommand({
      file: 'schtasks.exe',
      args: ['/Query', '/TN', DAILY_REGISTRY_BACKUP_TASK, '/FO', 'LIST'],
    }, { ...COMMAND_OPTS, timeout: 30_000 })
    return {
      id: 'daily-registry-backup',
      available: true,
      enabled: true,
      status: 'enabled',
      details: 'Daily registry backup task exists.',
      log: result.stdout + result.stderr,
    }
  } catch (err) {
    return {
      id: 'daily-registry-backup',
      available: true,
      enabled: false,
      status: 'disabled',
      details: 'Daily registry backup task is not present.',
      log: errorMessage(err),
    }
  }
}

function parseOptionalFeatureLines(output: string): Array<{ name: string; state: string }> {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('FEATURE|'))
    .map((line) => {
      const [, name, state] = line.split('|')
      return { name, state }
    })
    .filter((entry) => entry.name.length > 0)
}

function parseActionLines(output: string): Array<{ ok: boolean; id: string; message: string }> {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('OK|') || line.startsWith('ERR|'))
    .map((line) => {
      const [kind, id, ...rest] = line.split('|')
      return { ok: kind === 'OK', id, message: rest.join('|') }
    })
}

function parseOpenSshStatus(output: string): UtilityConfigOpenSshStatusResult {
  const cap = output.match(/^CAP\|(.+)$/m)?.[1]?.trim() ?? 'Unknown'
  const service = output.match(/^SVC\|([^|]+)\|?([^|]*)/m)
  const serviceState = service?.[1]?.trim() ?? 'Missing'
  const startupType = service?.[2]?.trim() || null
  const installed = /^installed$/i.test(cap)
  const serviceRunning = /^running$/i.test(serviceState)

  return {
    available: true,
    installed,
    serviceRunning,
    startupType,
    details: `Capability: ${cap}; sshd: ${serviceState}${startupType ? ` (${startupType})` : ''}`,
  }
}

function optionalFeatureStatusScript(featureNames: string[]): string {
  return `
    $names = @(${featureNames.map(psString).join(',')})
    foreach ($name in $names) {
      try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
        Write-Output "FEATURE|$($feature.FeatureName)|$($feature.State)"
      } catch {
        Write-Output "FEATURE|$name|Unavailable"
      }
    }
  `
}

function optionalFeatureEnableScript(featureNames: string[]): string {
  return `
    $names = @(${featureNames.map(psString).join(',')})
    foreach ($name in $names) {
      try {
        Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart -ErrorAction Stop | Out-Null
        Write-Output "OK|$name|Enabled"
      } catch {
        $message = ($_.Exception.Message -replace '\\r?\\n', ' ')
        Write-Output "ERR|$name|$message"
      }
    }
  `
}

function windowsUpdateRestartScript(): string {
  return `
    $services = @('wuauserv','bits','cryptsvc')
    foreach ($service in $services) {
      try { Stop-Service -Name $service -Force -ErrorAction SilentlyContinue } catch {}
    }
    foreach ($service in $services) {
      try {
        Start-Service -Name $service -ErrorAction Stop
        Write-Output "OK|$service|Restarted"
      } catch {
        $message = ($_.Exception.Message -replace '\\r?\\n', ' ')
        Write-Output "ERR|$service|$message"
      }
    }
  `
}

function openSshStatusScript(): string {
  return `
    $cap = Get-WindowsCapability -Online -Name ${psString(OPENSSH_SERVER_CAPABILITY)} -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cap) { Write-Output "CAP|$($cap.State)" } else { Write-Output "CAP|Missing" }
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc) { Write-Output "SVC|$($svc.Status)|$($svc.StartType)" } else { Write-Output "SVC|Missing|" }
  `
}

function openSshEnableScript(): string {
  return `
    $cap = Get-WindowsCapability -Online -Name ${psString(OPENSSH_SERVER_CAPABILITY)} -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cap -or $cap.State -ne 'Installed') {
      Add-WindowsCapability -Online -Name ${psString(OPENSSH_SERVER_CAPABILITY)} -ErrorAction Stop | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name sshd -ErrorAction SilentlyContinue
    Write-Output "OK|openssh-server|Installed and start requested"
  `
}

function dailyRegistryBackupTaskAction(): string {
  const script = [
    "$dest = Join-Path $env:ProgramData 'Bulwrk\\RegistryBackup'",
    'New-Item -ItemType Directory -Force -Path $dest | Out-Null',
    "reg.exe export HKLM\\SOFTWARE (Join-Path $dest 'SOFTWARE.reg') /y",
    "reg.exe export HKLM\\SYSTEM (Join-Path $dest 'SYSTEM.reg') /y",
    "reg.exe export HKU\\.DEFAULT (Join-Path $dest 'DEFAULT.reg') /y",
  ].join('; ')
  return `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "${script.replace(/"/g, '\\"')}"`
}

function powershellCommand(script: string): UtilityCommandSpec {
  return {
    file: 'powershell.exe',
    args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', psUtf8(script)],
  }
}

function psString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

async function runCommand(
  command: UtilityCommandSpec,
  opts: typeof COMMAND_OPTS = COMMAND_OPTS,
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(command.file, command.args, opts) as Promise<{ stdout: string; stderr: string }>
}

function findFeature(id: UtilityConfigFeatureId): UtilityConfigFeatureDefinition | undefined {
  return UTILITY_CONFIG_FEATURES.find((feature) => feature.id === id)
}

function findPanel(id: UtilityLegacyPanelId): UtilityLegacyPanelDefinition | undefined {
  return UTILITY_LEGACY_PANELS.find((panel) => panel.id === id)
}

function findFix(id: UtilityConfigFixId): UtilityConfigFixDefinition | undefined {
  return UTILITY_CONFIG_FIXES.find((fix) => fix.id === id)
}

function fixSummary(fix: UtilityConfigFixDefinition): string {
  if (fix.id === 'reset-windows-update') {
    return 'Windows Update services restart completed; cache folders were left intact.'
  }
  if (fix.id === 'system-corruption-scan') {
    return 'SFC and DISM system repair commands completed.'
  }
  return `${fix.name} completed.`
}

function unavailableFeatureStatus(id: string, details: string): UtilityConfigFeatureStatusResult {
  return { id, available: false, enabled: null, status: 'unavailable', details }
}

function needsAdminResult(id: string): UtilityConfigActionResult {
  return {
    id,
    success: false,
    summary: 'Administrator privileges required.',
    needsAdmin: true,
    requiresReboot: false,
  }
}

function actionError(id: string, error: string): UtilityConfigActionResult {
  return {
    id,
    success: false,
    summary: error,
    error,
    needsAdmin: false,
    requiresReboot: false,
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error'
}
