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

import { registerDeviceApiIpc } from './device-api.ipc'
import { deviceCommandAgent } from '../services/device-command-agent'

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

  it('registers enroll/unenroll/status/poll handlers', () => {
    registerDeviceApiIpc()
    expect(handleMap.has('device-api:enroll')).toBe(true)
    expect(handleMap.has('device-api:unenroll')).toBe(true)
    expect(handleMap.has('device-api:get-status')).toBe(true)
    expect(handleMap.has('device-api:poll-now')).toBe(true)
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
})
