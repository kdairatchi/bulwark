import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type {
  UtilityConfigActionResult,
  UtilityConfigCatalogResult,
  UtilityConfigFeatureStatusResult,
  UtilityConfigFixProgress,
  UtilityConfigOpenSshStatusResult,
  UtilityLegacyPanelLaunchResult,
} from '../../shared/types'
import type { WindowGetter } from './index'
import {
  enableOpenSshServer,
  enableUtilityConfigFeature,
  getOpenSshStatus,
  getUtilityConfigCatalog,
  getUtilityConfigFeatureStatus,
  launchUtilityLegacyPanel,
  revertUtilityConfigFeature,
  runUtilityConfigFix,
  validateUtilityConfigFeatureId,
  validateUtilityConfigFixId,
  validateUtilityLegacyPanelId,
} from '../services/utility-config'

export function registerUtilityConfigIpc(getWindow: WindowGetter): void {
  const sendProgress = (data: UtilityConfigFixProgress): void => {
    const win = getWindow()
    if (win && !win.isDestroyed()) win.webContents.send(IPC.UTILITY_CONFIG_FIX_PROGRESS, data)
  }

  ipcMain.handle(IPC.UTILITY_CONFIG_CATALOG, async (): Promise<UtilityConfigCatalogResult> => {
    return getUtilityConfigCatalog()
  })

  ipcMain.handle(
    IPC.UTILITY_CONFIG_FEATURE_STATUS,
    async (_event, id: unknown): Promise<UtilityConfigFeatureStatusResult> => {
      const validId = validateUtilityConfigFeatureId(id)
      if (!validId) {
        return {
          id: typeof id === 'string' ? id : '*',
          available: false,
          enabled: null,
          status: 'unavailable',
          details: 'Invalid feature ID',
        }
      }
      return getUtilityConfigFeatureStatus(validId)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_FEATURE_ENABLE,
    async (_event, id: unknown): Promise<UtilityConfigActionResult> => {
      const validId = validateUtilityConfigFeatureId(id)
      if (!validId) return invalidActionResult(typeof id === 'string' ? id : '*', 'Invalid feature ID')
      return enableUtilityConfigFeature(validId)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_FEATURE_REVERT,
    async (_event, id: unknown): Promise<UtilityConfigActionResult> => {
      const validId = validateUtilityConfigFeatureId(id)
      if (!validId) return invalidActionResult(typeof id === 'string' ? id : '*', 'Invalid feature ID')
      return revertUtilityConfigFeature(validId)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_PANEL_LAUNCH,
    async (_event, id: unknown): Promise<UtilityLegacyPanelLaunchResult> => {
      const validId = validateUtilityLegacyPanelId(id)
      if (!validId) return { id: typeof id === 'string' ? id : '*', launched: false, error: 'Invalid panel ID' }
      return launchUtilityLegacyPanel(validId)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_OPENSSH_STATUS,
    async (): Promise<UtilityConfigOpenSshStatusResult> => {
      return getOpenSshStatus()
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_OPENSSH_ENABLE,
    async (): Promise<UtilityConfigActionResult> => {
      return enableOpenSshServer()
    },
  )

  ipcMain.handle(
    IPC.UTILITY_CONFIG_FIX_RUN,
    async (_event, id: unknown): Promise<UtilityConfigActionResult> => {
      const validId = validateUtilityConfigFixId(id)
      if (!validId) return invalidActionResult(typeof id === 'string' ? id : '*', 'Invalid fix ID')
      return runUtilityConfigFix(validId, sendProgress)
    },
  )
}

function invalidActionResult(id: string, summary: string): UtilityConfigActionResult {
  return {
    id,
    success: false,
    summary,
    error: summary,
    needsAdmin: false,
    requiresReboot: false,
  }
}
