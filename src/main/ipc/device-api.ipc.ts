import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import { deviceCommandAgent } from '../services/device-command-agent'
import {
  DashboardApiClient,
  resolveDashboardBaseUrl,
} from '../services/dashboard-api-client'
import { DeviceApiHttpError } from '../services/device-api-client'

function asRecord(payload: unknown): Record<string, unknown> {
  return (payload ?? {}) as Record<string, unknown>
}

function clientFromPayload(payload: unknown): DashboardApiClient {
  const o = asRecord(payload)
  const baseUrl = resolveDashboardBaseUrl(typeof o.baseUrl === 'string' ? o.baseUrl : undefined)
  return new DashboardApiClient({ baseUrl })
}

function httpErr(err: unknown): { success: false; error: string } {
  if (err instanceof DeviceApiHttpError) {
    const body = err.body as { error?: string } | null
    return { success: false, error: body?.error || err.message }
  }
  return { success: false, error: err instanceof Error ? err.message : String(err) }
}

export function registerDeviceApiIpc(): void {
  ipcMain.handle(IPC.DEVICE_API_ENROLL, async (_event, payload: unknown) => {
    const o = asRecord(payload)
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

  ipcMain.handle(IPC.DASHBOARD_CREATE_PAIRING_CODE, async (_event, payload: unknown) => {
    try {
      const result = await clientFromPayload(payload).createPairingCode()
      return { success: true as const, ...result }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_LIST_DEVICES, async (_event, payload: unknown) => {
    try {
      const devices = await clientFromPayload(payload).listDevices()
      return { success: true as const, devices }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_ISOLATE, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : ''
    if (!deviceId) return { success: false, error: 'deviceId is required' }
    const reason = typeof o.reason === 'string' ? o.reason : undefined
    try {
      const result = await clientFromPayload(payload).isolateDevice(deviceId, reason)
      return { success: true as const, ...result }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_CLEAR_ISOLATION, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : ''
    if (!deviceId) return { success: false, error: 'deviceId is required' }
    try {
      const result = await clientFromPayload(payload).clearIsolation(deviceId)
      return { success: true as const, ...result }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_PUT_POLICY, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : ''
    if (!deviceId) return { success: false, error: 'deviceId is required' }
    const patch: Record<string, unknown> = {}
    if (typeof o.dnsGuardRequired === 'boolean') patch.dnsGuardRequired = o.dnsGuardRequired
    if (typeof o.allowInstallUnknown === 'boolean') patch.allowInstallUnknown = o.allowInstallUnknown
    if (Array.isArray(o.blockedDomains)) {
      patch.blockedDomains = o.blockedDomains.filter((d): d is string => typeof d === 'string')
    }
    if (Array.isArray(o.isolationAllowlist)) {
      patch.isolationAllowlist = o.isolationAllowlist.filter((d): d is string => typeof d === 'string')
    }
    try {
      const result = await clientFromPayload(payload).putPolicy(deviceId, patch)
      return { success: true as const, ...result }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_LIST_EVENTS, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : undefined
    try {
      const events = await clientFromPayload(payload).listNetworkEvents(deviceId)
      return { success: true as const, events }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_LIST_FINDINGS, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : undefined
    try {
      const findings = await clientFromPayload(payload).listFindings(deviceId)
      return { success: true as const, findings }
    } catch (err) {
      return httpErr(err)
    }
  })

  ipcMain.handle(IPC.DASHBOARD_ISSUE_COMMAND, async (_event, payload: unknown) => {
    const o = asRecord(payload)
    const deviceId = typeof o.deviceId === 'string' ? o.deviceId : ''
    const type = typeof o.type === 'string' ? o.type : ''
    if (!deviceId) return { success: false, error: 'deviceId is required' }
    if (!type) return { success: false, error: 'type is required' }
    const parameters = (o.parameters && typeof o.parameters === 'object')
      ? o.parameters as Record<string, unknown>
      : {}
    try {
      const result = await clientFromPayload(payload).issueCommand(deviceId, type, parameters)
      return { success: true as const, ...result }
    } catch (err) {
      return httpErr(err)
    }
  })
}
