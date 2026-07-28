import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type { WindowGetter } from './index'
import type {
  UtilityInstallActionResult,
  UtilityInstallCatalogResult,
  UtilityInstallProgress,
  UtilityWingetAction,
} from '../../shared/types'
import {
  getInstalledWingetPackages,
  getUtilityAppCatalog,
  isWingetAvailable,
  runUtilityInstallActions,
  upgradeAllWingetPackages,
} from '../services/utility-install'
import { isUtilityCatalogPackageId } from '../services/utility-apps.catalog'

const ACTIONS = new Set<UtilityWingetAction>(['install', 'upgrade', 'uninstall'])

export function registerUtilityInstallIpc(getWindow: WindowGetter): void {
  const sendProgress = (data: UtilityInstallProgress): void => {
    const win = getWindow()
    if (win && !win.isDestroyed()) win.webContents.send(IPC.UTILITY_INSTALL_PROGRESS, data)
  }

  ipcMain.handle(IPC.UTILITY_INSTALL_CATALOG, async (): Promise<UtilityInstallCatalogResult> => {
    if (process.platform !== 'win32') {
      return { wingetAvailable: false, apps: [], installed: {} }
    }
    const [wingetAvailable, installed] = await Promise.all([
      isWingetAvailable(),
      getInstalledWingetPackages(),
    ])
    return {
      wingetAvailable,
      apps: getUtilityAppCatalog(),
      installed: wingetAvailable ? installed : {},
    }
  })

  ipcMain.handle(IPC.UTILITY_INSTALL_REFRESH, async (): Promise<UtilityInstallCatalogResult> => {
    if (process.platform !== 'win32') {
      return { wingetAvailable: false, apps: [], installed: {} }
    }
    const wingetAvailable = await isWingetAvailable()
    const installed = wingetAvailable ? await getInstalledWingetPackages() : {}
    return {
      wingetAvailable,
      apps: getUtilityAppCatalog(),
      installed,
    }
  })

  ipcMain.handle(
    IPC.UTILITY_INSTALL_RUN,
    async (
      _event,
      payload: { action?: unknown; ids?: unknown },
    ): Promise<UtilityInstallActionResult> => {
      const action = typeof payload?.action === 'string' ? payload.action : ''
      if (!ACTIONS.has(action as UtilityWingetAction)) {
        return { succeeded: 0, failed: 0, errors: [{ id: '*', reason: 'Invalid action' }] }
      }
      if (!Array.isArray(payload?.ids) || payload.ids.length === 0) {
        return { succeeded: 0, failed: 0, errors: [] }
      }
      const ids = payload.ids
        .filter((id): id is string => typeof id === 'string' && isUtilityCatalogPackageId(id))
        .slice(0, 100)
      if (ids.length === 0) {
        return { succeeded: 0, failed: 0, errors: [{ id: '*', reason: 'No valid package IDs' }] }
      }
      return runUtilityInstallActions(action as UtilityWingetAction, ids, sendProgress)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_INSTALL_UPGRADE_ALL,
    async (): Promise<UtilityInstallActionResult> => {
      return upgradeAllWingetPackages(sendProgress)
    },
  )
}
