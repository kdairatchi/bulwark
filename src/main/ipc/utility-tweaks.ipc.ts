import { ipcMain, shell } from 'electron'
import { existsSync } from 'fs'
import { join } from 'path'
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

function getShutUp10Candidates(): string[] {
  const roots = [
    process.env.ProgramFiles,
    process.env['ProgramFiles(x86)'],
    process.env.LOCALAPPDATA,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0)

  const relativePaths = [
    ['O&O ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'O&O ShutUp10++', 'OOSU10.exe'],
    ['OOSU10', 'OOSU10.exe'],
  ]

  return roots.flatMap((root) => relativePaths.map((parts) => join(root, ...parts)))
}

async function launchShutUp10(): Promise<UtilityShutUpLaunchResult> {
  if (process.platform === 'win32') {
    for (const candidate of getShutUp10Candidates()) {
      if (!existsSync(candidate)) continue
      const error = await shell.openPath(candidate)
      if (!error) return { opened: true, fallback: false, path: candidate }
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
