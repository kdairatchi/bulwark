import { ipcMain, shell } from 'electron'
import { existsSync } from 'fs'
import { isAbsolute, relative, resolve } from 'path'
import { IPC } from '../../shared/channels'
import type {
  UtilityPowerPlanSetResult,
  UtilityPowerPlanState,
  UtilityPowerPlanTarget,
  UtilityShutUpLaunchResult,
  UtilityTweakActionResult,
  UtilityTweakMetadata,
  UtilityTweaksScanResult,
} from '../../shared/types'
import {
  applyTweaks,
  getCatalog,
  getUtilityPowerPlan,
  revertTweaks,
  scanTweaks,
  setUtilityPowerPlan,
  UTILITY_POWER_PLAN_TARGETS,
  validateUtilityTweakIds,
} from '../services/utility-tweaks'

function validatePowerPlanTarget(input: unknown): UtilityPowerPlanTarget | null {
  if (typeof input !== 'string') return null
  return UTILITY_POWER_PLAN_TARGETS.includes(input as UtilityPowerPlanTarget)
    ? input as UtilityPowerPlanTarget
    : null
}

const SHUTUP10_DOWNLOAD_URL = 'https://www.oo-software.com/en/shutup10'

function pathContainsParentSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..')
}

function isPathUnderRoot(candidate: string, root: string): boolean {
  const rel = relative(root, candidate)
  return rel === '' || (rel.length > 0 && !rel.startsWith('..') && !isAbsolute(rel))
}

export function getResolvedShutUp10Roots(env: NodeJS.ProcessEnv = process.env): string[] {
  const roots = [
    env.ProgramFiles,
    env['ProgramFiles(x86)'],
    env.LOCALAPPDATA,
  ].filter((value): value is string =>
    typeof value === 'string'
    && value.length > 0
    && isAbsolute(value)
    && !pathContainsParentSegment(value)
  )

  return [...new Set(roots.map((root) => resolve(root)))]
}

export function isShutUp10CandidatePathAllowed(candidate: string, roots = getResolvedShutUp10Roots()): boolean {
  if (pathContainsParentSegment(candidate)) return false
  const resolvedCandidate = resolve(candidate)
  return roots.some((root) => isPathUnderRoot(resolvedCandidate, root))
}

export function getShutUp10Candidates(env: NodeJS.ProcessEnv = process.env): string[] {
  const roots = getResolvedShutUp10Roots(env)

  const relativePaths = [
    ['O&O ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'O&O ShutUp10++', 'OOSU10.exe'],
    ['OOSU10', 'OOSU10.exe'],
  ]

  return roots.flatMap((root) =>
    relativePaths
      .map((parts) => resolve(root, ...parts))
      .filter((candidate) => isShutUp10CandidatePathAllowed(candidate, roots))
  )
}

async function launchShutUp10(): Promise<UtilityShutUpLaunchResult> {
  if (process.platform === 'win32') {
    const roots = getResolvedShutUp10Roots()
    for (const candidate of getShutUp10Candidates()) {
      const resolvedCandidate = resolve(candidate)
      if (!isShutUp10CandidatePathAllowed(resolvedCandidate, roots)) continue
      if (!existsSync(resolvedCandidate)) continue
      const error = await shell.openPath(resolvedCandidate)
      if (!error) return { opened: true, fallback: false, path: resolvedCandidate }
    }
  }

  await shell.openExternal(SHUTUP10_DOWNLOAD_URL)
  return { opened: true, fallback: true, path: SHUTUP10_DOWNLOAD_URL }
}

export function registerUtilityTweaksIpc(): void {
  ipcMain.handle(IPC.UTILITY_TWEAKS_CATALOG, async (): Promise<UtilityTweakMetadata[]> => {
    if (process.platform !== 'win32') return []
    return getCatalog()
  })

  ipcMain.handle(IPC.UTILITY_TWEAKS_SCAN, async (): Promise<UtilityTweaksScanResult> => {
    return scanTweaks()
  })

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_APPLY,
    async (_event, ids: unknown): Promise<UtilityTweakActionResult> => {
      const validIds = validateUtilityTweakIds(ids)
      if (!validIds) {
        return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
      }
      return applyTweaks(validIds)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_REVERT,
    async (_event, ids: unknown): Promise<UtilityTweakActionResult> => {
      const validIds = validateUtilityTweakIds(ids)
      if (!validIds) {
        return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
      }
      return revertTweaks(validIds)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_POWER_PLAN_GET,
    async (): Promise<UtilityPowerPlanState> => getUtilityPowerPlan(),
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_POWER_PLAN_SET,
    async (_event, target: unknown): Promise<UtilityPowerPlanSetResult> => {
      const validTarget = validatePowerPlanTarget(target)
      if (!validTarget) return { success: false, error: 'Invalid power plan target' }
      return setUtilityPowerPlan(validTarget)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_SHUTUP10_LAUNCH,
    async (): Promise<UtilityShutUpLaunchResult> => launchShutUp10(),
  )
}
