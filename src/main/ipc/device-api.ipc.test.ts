import { describe, it, expect, vi, beforeEach } from 'vitest'

const handleMap = new Map<string, (...args: unknown[]) => unknown>()

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: unknown[]) => unknown) => {
      handleMap.set(channel, handler)
    }),
  },
}))

vi.mock('../../shared/channels', () => ({
  IPC: {
    DEVICE_API_ENROLL: 'device-api:enroll',
    DEVICE_API_UNENROLL: 'device-api:unenroll',
    DEVICE_API_GET_STATUS: 'device-api:get-status',
    DEVICE_API_POLL_NOW: 'device-api:poll-now',
    DASHBOARD_CREATE_PAIRING_CODE: 'dashboard:create-pairing-code',
    DASHBOARD_BOOTSTRAP: 'dashboard:bootstrap',
    DASHBOARD_LIST_DEVICES: 'dashboard:list-devices',
    DASHBOARD_ISOLATE: 'dashboard:isolate',
    DASHBOARD_CLEAR_ISOLATION: 'dashboard:clear-isolation',
    DASHBOARD_PUT_POLICY: 'dashboard:put-policy',
    DASHBOARD_LIST_EVENTS: 'dashboard:list-events',
    DASHBOARD_LIST_FINDINGS: 'dashboard:list-findings',
    DASHBOARD_ISSUE_COMMAND: 'dashboard:issue-command',
    DASHBOARD_REQUEST_SCAN: 'dashboard:request-scan',
    DASHBOARD_REVIEW_FINDING: 'dashboard:review-finding',
    DASHBOARD_LIST_BREACH_MONITORS: 'dashboard:list-breach-monitors',
    DASHBOARD_CREATE_BREACH_MONITOR: 'dashboard:create-breach-monitor',
    DASHBOARD_DELETE_BREACH_MONITOR: 'dashboard:delete-breach-monitor',
    DASHBOARD_ACK_BREACHES: 'dashboard:ack-breaches',
    DASHBOARD_REFRESH_BREACH_MONITORS: 'dashboard:refresh-breach-monitors',
    DASHBOARD_GET_REPORT: 'dashboard:get-report',
    DASHBOARD_LIST_ALERTS: 'dashboard:list-alerts',
  },
}))

vi.mock('../services/device-command-agent', () => ({
  deviceCommandAgent: {
    enroll: vi.fn(),
    unenroll: vi.fn(),
    getStatus: vi.fn(),
    tick: vi.fn(),
  },
}))

vi.mock('../services/dashboard-api-client', () => {
  const instance = {
    createPairingCode: vi.fn(),
    bootstrap: vi.fn(),
    listDevices: vi.fn(),
    isolateDevice: vi.fn(),
    clearIsolation: vi.fn(),
    putPolicy: vi.fn(),
    listNetworkEvents: vi.fn(),
    listFindings: vi.fn(),
    issueCommand: vi.fn(),
    requestScan: vi.fn(),
    reviewFinding: vi.fn(),
    listBreachMonitors: vi.fn(),
    createBreachMonitor: vi.fn(),
    deleteBreachMonitor: vi.fn(),
    acknowledgeBreaches: vi.fn(),
    refreshBreachMonitors: vi.fn(),
    getFleetReport: vi.fn(),
    listAlerts: vi.fn(),
  }
  class MockDashboardApiClient {
    constructor() {
      return instance
    }
  }
  return {
    DashboardApiClient: MockDashboardApiClient,
    resolveDashboardBaseUrl: (v?: string) => v || 'http://127.0.0.1:8787',
    __mockDashboard: instance,
  }
})

import { registerDeviceApiIpc } from './device-api.ipc'
import { deviceCommandAgent } from '../services/device-command-agent'
import * as dashboardMod from '../services/dashboard-api-client'

const mockAgent = deviceCommandAgent as unknown as {
  enroll: ReturnType<typeof vi.fn>
  unenroll: ReturnType<typeof vi.fn>
  getStatus: ReturnType<typeof vi.fn>
  tick: ReturnType<typeof vi.fn>
}

function invoke(channel: string, ...args: unknown[]) {
  const handler = handleMap.get(channel)
  if (!handler) throw new Error(`No handler for ${channel}`)
  return handler({}, ...args)
}

describe('device-api IPC', () => {
  beforeEach(() => {
    handleMap.clear()
    vi.clearAllMocks()
  })

  it('registers enroll/unenroll/status/poll and dashboard handlers', () => {
    registerDeviceApiIpc()
    expect(handleMap.has('device-api:enroll')).toBe(true)
    expect(handleMap.has('device-api:unenroll')).toBe(true)
    expect(handleMap.has('device-api:get-status')).toBe(true)
    expect(handleMap.has('device-api:poll-now')).toBe(true)
    expect(handleMap.has('dashboard:list-devices')).toBe(true)
    expect(handleMap.has('dashboard:bootstrap')).toBe(true)
    expect(handleMap.has('dashboard:isolate')).toBe(true)
    expect(handleMap.has('dashboard:list-events')).toBe(true)
    expect(handleMap.has('dashboard:list-breach-monitors')).toBe(true)
    expect(handleMap.has('dashboard:create-breach-monitor')).toBe(true)
    expect(handleMap.has('dashboard:get-report')).toBe(true)
    expect(handleMap.has('dashboard:list-alerts')).toBe(true)
  })

  it('bootstraps dashboard token via client', async () => {
    registerDeviceApiIpc()
    const dash = (dashboardMod as unknown as { __mockDashboard: {
      bootstrap: ReturnType<typeof vi.fn>
    } }).__mockDashboard
    dash.bootstrap.mockResolvedValue({ token: 'tok_test', bootstrapAllowed: true })
    const result = await invoke('dashboard:bootstrap', { baseUrl: 'http://127.0.0.1:8787' })
    expect(result).toEqual({ success: true, token: 'tok_test', bootstrapAllowed: true })
  })

  it('rejects short pairing codes', async () => {
    registerDeviceApiIpc()
    const result = await invoke('device-api:enroll', { code: 'ab' })
    expect(result).toEqual({ success: false, error: 'Pairing code is required' })
    expect(mockAgent.enroll).not.toHaveBeenCalled()
  })

  it('forwards enroll payload', async () => {
    registerDeviceApiIpc()
    mockAgent.enroll.mockResolvedValue({ success: true, deviceId: 'dev_1' })
    const result = await invoke('device-api:enroll', {
      code: 'ABCD12',
      name: 'Kitchen',
      baseUrl: 'http://127.0.0.1:8787',
    })
    expect(mockAgent.enroll).toHaveBeenCalledWith({
      code: 'ABCD12',
      name: 'Kitchen',
      baseUrl: 'http://127.0.0.1:8787',
    })
    expect(result).toEqual({ success: true, deviceId: 'dev_1' })
  })

  it('poll-now ticks then returns status', async () => {
    registerDeviceApiIpc()
    mockAgent.tick.mockResolvedValue(undefined)
    mockAgent.getStatus.mockReturnValue({ enrolled: true, running: true })
    const result = await invoke('device-api:poll-now')
    expect(mockAgent.tick).toHaveBeenCalled()
    expect(result).toEqual({ enrolled: true, running: true })
  })

  it('lists devices via dashboard client', async () => {
    registerDeviceApiIpc()
    const dash = (dashboardMod as unknown as { __mockDashboard: {
      listDevices: ReturnType<typeof vi.fn>
    } }).__mockDashboard
    dash.listDevices.mockResolvedValue([{ id: 'dev_1', name: 'TV' }])
    const result = await invoke('dashboard:list-devices', { baseUrl: 'http://127.0.0.1:8787' })
    expect(result).toEqual({ success: true, devices: [{ id: 'dev_1', name: 'TV' }] })
  })

  it('requires deviceId for isolate', async () => {
    registerDeviceApiIpc()
    const result = await invoke('dashboard:isolate', { baseUrl: 'http://127.0.0.1:8787' })
    expect(result).toEqual({ success: false, error: 'deviceId is required' })
  })

  it('queues a remote scan via requestScan', async () => {
    registerDeviceApiIpc()
    const dash = (dashboardMod as unknown as { __mockDashboard: {
      requestScan: ReturnType<typeof vi.fn>
    } }).__mockDashboard
    dash.requestScan.mockResolvedValue({ command: { commandId: 'cmd_s', type: 'RUN_HEALTH_ASSESSMENT' } })
    const result = await invoke('dashboard:request-scan', {
      baseUrl: 'http://127.0.0.1:8787',
      deviceId: 'dev_1',
      kind: 'health',
    })
    expect(dash.requestScan).toHaveBeenCalledWith('dev_1', 'health', { scope: undefined })
    expect(result).toEqual({ success: true, command: { commandId: 'cmd_s', type: 'RUN_HEALTH_ASSESSMENT' } })
  })

  it('reviews a finding via dashboard client', async () => {
    registerDeviceApiIpc()
    const dash = (dashboardMod as unknown as { __mockDashboard: {
      reviewFinding: ReturnType<typeof vi.fn>
    } }).__mockDashboard
    dash.reviewFinding.mockResolvedValue({
      finding: { id: 'f1', status: 'false_positive' },
      securityScore: 100,
      openFindingsCount: 0,
    })
    const result = await invoke('dashboard:review-finding', {
      findingId: 'f1',
      status: 'false_positive',
    })
    expect(dash.reviewFinding).toHaveBeenCalledWith('f1', 'false_positive', undefined)
    expect(result).toMatchObject({ success: true, securityScore: 100 })
  })
})
