import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type {
  UtilityOsUpdateCheckResult,
  UtilityOsUpdateInstallResult,
  UtilityUpdatesHelperResult,
  UtilityUpdatesPauseResult,
  UtilityUpdatesResumeResult,
  UtilityUpdatesStatus,
} from '../../shared/types'
import {
  checkUtilityOsUpdates,
  getUtilityUpdatesStatus,
  installUtilityOsUpdates,
  pauseUtilityUpdates,
  resumeUtilityUpdates,
  runUtilityUpdatesHelper,
  validateUtilityUpdatesHelperId,
  validateUtilityUpdatesPauseDays,
} from '../services/utility-updates'

export function registerUtilityUpdatesIpc(): void {
  ipcMain.handle(IPC.UTILITY_UPDATES_STATUS, async (): Promise<UtilityUpdatesStatus> => {
    return getUtilityUpdatesStatus()
  })

  ipcMain.handle(IPC.UTILITY_UPDATES_OS_CHECK, async (): Promise<UtilityOsUpdateCheckResult> => {
    return checkUtilityOsUpdates()
  })

  ipcMain.handle(IPC.UTILITY_UPDATES_OS_INSTALL, async (): Promise<UtilityOsUpdateInstallResult> => {
    return installUtilityOsUpdates()
  })

  ipcMain.handle(
    IPC.UTILITY_UPDATES_PAUSE,
    async (_event, days: unknown): Promise<UtilityUpdatesPauseResult> => {
      const validDays = validateUtilityUpdatesPauseDays(days)
      if (!validDays) {
        return { success: false, needsAdmin: false, error: 'Invalid pause duration' }
      }
      return pauseUtilityUpdates(validDays)
    },
  )

  ipcMain.handle(IPC.UTILITY_UPDATES_RESUME, async (): Promise<UtilityUpdatesResumeResult> => {
    return resumeUtilityUpdates()
  })

  ipcMain.handle(
    IPC.UTILITY_UPDATES_HELPER,
    async (_event, id: unknown): Promise<UtilityUpdatesHelperResult> => {
      const validId = validateUtilityUpdatesHelperId(id)
      if (!validId) {
        return {
          id: typeof id === 'string' ? id : '*',
          success: false,
          summary: 'Invalid helper ID',
          error: 'Invalid helper ID',
          needsAdmin: false,
          requiresReboot: false,
        }
      }
      return runUtilityUpdatesHelper(validId)
    },
  )
}
