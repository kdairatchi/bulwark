import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type {
  UtilityPowerPlanSetResult,
  UtilityPowerPlanState,
  UtilityPowerPlanTarget,
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
}
