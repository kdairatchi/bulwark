import { execFile } from 'child_process'
import { promisify } from 'util'
import { createRestorePoint } from './restore-point'
import {
  UTILITY_TWEAK_CATALOG,
  type UtilityTweakDefinition,
} from './utility-tweaks.catalog'
import type {
  UtilityPowerPlanSetResult,
  UtilityPowerPlanState,
  UtilityPowerPlanTarget,
  UtilityTweakActionResult,
  UtilityTweakMetadata,
  UtilityTweaksScanResult,
} from '../../shared/types'

const execFileAsync = promisify(execFile)

export const POWER_PLAN_GUIDS = {
  balanced: '381b4222-f694-41f0-9685-ff5bb260df2e',
  ultimatePerformance: 'e9a42b02-d5df-448d-aa00-03f14749eb61',
} as const

export const UTILITY_POWER_PLAN_TARGETS: UtilityPowerPlanTarget[] = [
  'balanced',
  'ultimate-performance',
]

const POWER_PLAN_GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export interface ParsedPowerScheme {
  guid: string
  name: string
  active: boolean
}

export function isPowerPlanGuid(value: string): boolean {
  return POWER_PLAN_GUID_RE.test(value)
}

export function parseActivePowerSchemeGuid(output: string): string | null {
  const match = output.match(/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i)
  return match?.[1]?.toLowerCase() ?? null
}

export function parsePowerSchemeList(output: string): ParsedPowerScheme[] {
  const schemes: ParsedPowerScheme[] = []
  const lineRe = /Power Scheme GUID:\s*([0-9a-f-]{36})\s+\(([^)]+)\)\s*(\*)?/gi
  let match: RegExpExecArray | null
  while ((match = lineRe.exec(output)) !== null) {
    if (!isPowerPlanGuid(match[1])) continue
    schemes.push({
      guid: match[1].toLowerCase(),
      name: match[2].trim(),
      active: match[3] === '*',
    })
  }
  return schemes
}

export function classifyPowerPlanGuid(guid: string | null): UtilityPowerPlanState['active'] {
  if (!guid) return 'unknown'
  const normalized = guid.toLowerCase()
  if (normalized === POWER_PLAN_GUIDS.balanced) return 'balanced'
  if (normalized === POWER_PLAN_GUIDS.ultimatePerformance) return 'ultimate-performance'
  return 'other'
}

export function listTweaks(): UtilityTweakMetadata[] {
  return UTILITY_TWEAK_CATALOG.map(toMetadata)
}

export const getCatalog = listTweaks

export function validateUtilityTweakIds(ids: unknown, maxItems = 100): string[] | null {
  if (!Array.isArray(ids) || ids.length > maxItems) return null
  const known = new Set(UTILITY_TWEAK_CATALOG.map((t) => t.id))
  const unique: string[] = []
  const seen = new Set<string>()
  for (const id of ids) {
    if (typeof id !== 'string' || !known.has(id)) return null
    if (!seen.has(id)) {
      seen.add(id)
      unique.push(id)
    }
  }
  return unique
}

export async function scanTweaks(): Promise<UtilityTweaksScanResult> {
  if (process.platform !== 'win32') {
    return { available: false, tweaks: [], applied: {}, powerPlan: unavailablePowerPlan() }
  }

  const applied: Record<string, boolean> = {}
  for (const tweak of UTILITY_TWEAK_CATALOG) {
    try {
      applied[tweak.id] = await tweak.check()
    } catch {
      applied[tweak.id] = false
    }
  }

  return {
    available: true,
    tweaks: listTweaks(),
    applied,
    powerPlan: await getUtilityPowerPlan(),
  }
}

export async function applyTweaks(ids: string[]): Promise<UtilityTweakActionResult> {
  if (process.platform !== 'win32') {
    return { succeeded: 0, failed: ids.length, errors: ids.map((id) => ({ id, reason: 'Windows only' })) }
  }

  const validIds = validateUtilityTweakIds(ids)
  if (!validIds) {
    return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
  }
  if (validIds.length === 0) return { succeeded: 0, failed: 0, errors: [] }

  const restorePoint = await createRestorePoint('Bulwrk before Utility Tweaks')
  if (!restorePoint.success) {
    return {
      succeeded: 0,
      failed: validIds.length,
      errors: [{
        id: '*',
        reason: `Restore point failed: ${restorePoint.error ?? 'unknown error'}`,
      }],
      restorePoint,
    }
  }

  const result = await runTweaks(validIds, (tweak) => tweak.apply())
  return { ...result, restorePoint }
}

export async function revertTweaks(ids: string[]): Promise<UtilityTweakActionResult> {
  if (process.platform !== 'win32') {
    return { succeeded: 0, failed: ids.length, errors: ids.map((id) => ({ id, reason: 'Windows only' })) }
  }

  const validIds = validateUtilityTweakIds(ids)
  if (!validIds) {
    return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
  }
  if (validIds.length === 0) return { succeeded: 0, failed: 0, errors: [] }

  return runTweaks(validIds, (tweak) => tweak.revert())
}

export async function getUtilityPowerPlan(): Promise<UtilityPowerPlanState> {
  if (process.platform !== 'win32') return unavailablePowerPlan()
  try {
    const { stdout } = await runPowercfg(['/GETACTIVESCHEME'])
    const guid = parseActivePowerSchemeGuid(stdout)
    return {
      available: true,
      active: classifyPowerPlanGuid(guid),
      guid,
    }
  } catch (err) {
    return {
      available: false,
      active: 'unknown',
      guid: null,
      error: errorMessage(err),
    }
  }
}

export async function setUtilityPowerPlan(
  target: UtilityPowerPlanTarget,
): Promise<UtilityPowerPlanSetResult> {
  if (process.platform !== 'win32') return { success: false, error: 'Windows only' }
  if (!UTILITY_POWER_PLAN_TARGETS.includes(target)) {
    return { success: false, error: 'Invalid power plan target' }
  }

  try {
    const guid = target === 'balanced'
      ? POWER_PLAN_GUIDS.balanced
      : await getOrCreateUltimatePerformanceGuid()
    await runPowercfg(['/SETACTIVE', guid])
    return { success: true, state: await getUtilityPowerPlan() }
  } catch (err) {
    return { success: false, error: errorMessage(err) }
  }
}

function toMetadata(tweak: UtilityTweakDefinition): UtilityTweakMetadata {
  return {
    id: tweak.id,
    name: tweak.name,
    description: tweak.description,
    group: tweak.group,
    requiresAdmin: tweak.requiresAdmin,
  }
}

async function runTweaks(
  ids: string[],
  action: (tweak: UtilityTweakDefinition) => Promise<void>,
): Promise<UtilityTweakActionResult> {
  const byId = new Map(UTILITY_TWEAK_CATALOG.map((t) => [t.id, t]))
  let succeeded = 0
  let failed = 0
  const errors: UtilityTweakActionResult['errors'] = []

  for (const id of ids) {
    const tweak = byId.get(id)
    if (!tweak) {
      failed++
      errors.push({ id, reason: 'Unknown tweak ID' })
      continue
    }
    try {
      await action(tweak)
      succeeded++
    } catch (err) {
      failed++
      errors.push({ id, reason: errorMessage(err) })
    }
  }

  return { succeeded, failed, errors }
}

async function getOrCreateUltimatePerformanceGuid(): Promise<string> {
  const list = await runPowercfg(['/L'])
  const existing = parsePowerSchemeList(list.stdout).find((scheme) =>
    scheme.name.toLowerCase() === 'ultimate performance'
  )
  if (existing) return existing.guid

  const duplicated = await runPowercfg(['/DUPLICATESCHEME', POWER_PLAN_GUIDS.ultimatePerformance])
  return parseActivePowerSchemeGuid(duplicated.stdout) ?? POWER_PLAN_GUIDS.ultimatePerformance
}

function runPowercfg(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync('powercfg', args, {
    timeout: 10_000,
    windowsHide: true,
  }) as Promise<{ stdout: string; stderr: string }>
}

function unavailablePowerPlan(): UtilityPowerPlanState {
  return { available: false, active: 'unknown', guid: null }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error'
}
