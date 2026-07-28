import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import { deviceCommandAgent } from '../services/device-command-agent'

export function registerDeviceApiIpc(): void {
  ipcMain.handle(IPC.DEVICE_API_ENROLL, async (_event, payload: unknown) => {
    const o = (payload ?? {}) as Record<string, unknown>
    const code = typeof o.code === 'string' ? o.code : ''
    const name = typeof o.name === 'string' ? o.name : undefined
    const baseUrl = typeof o.baseUrl === 'string' ? o.baseUrl : undefined
    if (!code || code.trim().length < 4) {
      return { success: false, error: 'Pairing code is required' }
    }
    return deviceCommandAgent.enroll({ code, name, baseUrl })
  })

  ipcMain.handle(IPC.DEVICE_API_UNENROLL, async () => {
    await deviceCommandAgent.unenroll()
    return { success: true }
  })

  ipcMain.handle(IPC.DEVICE_API_GET_STATUS, () => {
    return deviceCommandAgent.getStatus()
  })

  ipcMain.handle(IPC.DEVICE_API_POLL_NOW, async () => {
    await deviceCommandAgent.tick()
    return deviceCommandAgent.getStatus()
  })
}
