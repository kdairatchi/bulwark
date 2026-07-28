import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import { scanForLeftovers } from '../services/uninstall-leftovers'
import { gatedCleanItems } from '../services/gated-clean'
import { cacheItems } from '../services/scan-cache'
import type { ScanResult, CleanResult } from '../../shared/types'
import type { WindowGetter } from './index'
import { validateStringArray, parseCleanOptions } from '../services/ipc-validation'

export function registerUninstallLeftoversIpc(getWindow: WindowGetter): void {
  ipcMain.handle(IPC.UNINSTALL_LEFTOVERS_SCAN, async (): Promise<ScanResult[]> => {
    const results = await scanForLeftovers(getWindow)

    // Cache all items so the clean handler can look them up by ID
    for (const result of results) {
      cacheItems(result.items)
    }

    return results
  })

  ipcMain.handle(IPC.UNINSTALL_LEFTOVERS_CLEAN, async (_event, itemIds: string[], options?: unknown): Promise<CleanResult> => {
    const valid = validateStringArray(itemIds)
    if (!valid) return { totalCleaned: 0, filesDeleted: 0, filesSkipped: 0, errors: [], needsElevation: false }
    return gatedCleanItems(valid, undefined, 'local', parseCleanOptions(options))
  })
}
