import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type { NetworkEvent } from '../../shared/network-guard'
import { buildIndicatorIndex, evaluateDestination, sanitizeIndicators } from '../services/network-guard'

export interface NetworkGuardCheckRequest {
  destination: string
  indicators?: unknown
  port?: number
  protocol?: 'tcp' | 'udp'
}

// Local-first: destination metadata is matched against a caller-supplied
// indicator feed entirely on-device. No payloads, no network calls.
export function registerNetworkGuardIpc(): void {
  ipcMain.handle(IPC.NETWORK_GUARD_CHECK, async (_e, req: NetworkGuardCheckRequest): Promise<NetworkEvent> => {
    const destination = typeof req?.destination === 'string' ? req.destination.trim() : ''
    if (!destination) throw new Error('A destination (domain or IP) is required')
    const indicators = sanitizeIndicators(req?.indicators)
    const index = buildIndicatorIndex(indicators)
    return evaluateDestination(
      { destination, port: req?.port, protocol: req?.protocol },
      index,
    )
  })
}
