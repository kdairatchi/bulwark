// Minimal Node http server wiring the pure handlers to routes. No framework —
// keeps the service dependency-free and runnable via `tsx`.

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'http'
import { DeviceStore } from './store'
import {
  createPairingCode, enrollDevice, listDevices, getDevice, listFindings,
  authenticateDevice, heartbeat, submitInventory, submitFindings,
  getServerKey, issueCommand, pollCommands, commandResult,
  type HandlerResult, type SignedRequest,
} from './handlers'

function send(res: ServerResponse, result: HandlerResult): void {
  const json = JSON.stringify(result.body)
  res.writeHead(result.status, { 'Content-Type': 'application/json' })
  res.end(json)
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    req.on('data', (c: Buffer) => {
      size += c.length
      if (size > 5 * 1024 * 1024) { reject(new Error('body too large')); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')))
    req.on('error', reject)
  })
}

function parseJson(raw: string): unknown {
  if (!raw) return {}
  try { return JSON.parse(raw) } catch { return null }
}

export function createDeviceApiServer(store: DeviceStore): Server {
  return createServer(async (req, res) => {
    try {
      const method = req.method ?? 'GET'
      const url = new URL(req.url ?? '/', 'http://localhost')
      const path = url.pathname
      const rawBody = method === 'GET' ? '' : await readBody(req)

      // ── Public routes ──
      if (method === 'POST' && path === '/v1/pairing-codes') return send(res, createPairingCode(store))
      if (method === 'POST' && path === '/v1/devices/enroll') {
        const body = parseJson(rawBody)
        if (body === null) return send(res, { status: 400, body: { error: 'invalid JSON' } })
        return send(res, enrollDevice(store, body))
      }
      if (method === 'GET' && path === '/v1/devices') return send(res, listDevices(store))
      if (method === 'GET' && path === '/v1/findings') {
        const deviceId = url.searchParams.get('deviceId') ?? undefined
        return send(res, listFindings(store, deviceId))
      }
      if (method === 'GET' && path === '/v1/server-key') return send(res, getServerKey(store))
      const deviceDetail = path.match(/^\/v1\/devices\/([^/]+)$/)
      if (method === 'GET' && deviceDetail) return send(res, getDevice(store, deviceDetail[1]))
      // Dashboard enqueues a signed command for a device.
      const enqueue = path.match(/^\/v1\/devices\/([^/]+)\/commands$/)
      if (method === 'POST' && enqueue) {
        const body = parseJson(rawBody)
        if (body === null) return send(res, { status: 400, body: { error: 'invalid JSON' } })
        return send(res, issueCommand(store, enqueue[1], body))
      }

      // ── Device-authenticated routes (all require a valid device signature) ──
      const telemetry = path.match(/^\/v1\/devices\/([^/]+)\/(heartbeat|inventory|findings)$/)
      const pollCmds = path.match(/^\/v1\/devices\/([^/]+)\/commands$/)
      const cmdResult = path.match(/^\/v1\/devices\/([^/]+)\/commands\/([^/]+)\/result$/)
      const authMatch =
        (method === 'POST' && telemetry) ||
        (method === 'GET' && pollCmds) ||
        (method === 'POST' && cmdResult)
      if (authMatch) {
        const pathDeviceId = authMatch[1]
        const signed: SignedRequest = {
          method, path, rawBody,
          headers: {
            deviceId: req.headers['x-device-id'] as string | undefined,
            timestamp: req.headers['x-timestamp'] as string | undefined,
            signature: req.headers['x-signature'] as string | undefined,
          },
        }
        const now = Date.now()
        const auth = authenticateDevice(store, signed, now)
        if (!auth.ok) return send(res, { status: auth.status, body: { error: auth.error } })
        if (auth.deviceId !== pathDeviceId) {
          return send(res, { status: 403, body: { error: 'device id mismatch' } })
        }
        if (method === 'GET' && pollCmds) return send(res, pollCommands(store, auth.deviceId))
        const body = parseJson(rawBody)
        if (body === null) return send(res, { status: 400, body: { error: 'invalid JSON' } })
        if (cmdResult) return send(res, commandResult(store, auth.deviceId, cmdResult[2], body))
        if (telemetry) {
          const action = telemetry[2]
          if (action === 'heartbeat') return send(res, heartbeat(store, auth.deviceId, now))
          if (action === 'inventory') return send(res, submitInventory(store, auth.deviceId, body))
          if (action === 'findings') return send(res, submitFindings(store, auth.deviceId, body))
        }
      }

      send(res, { status: 404, body: { error: 'not found' } })
    } catch (err) {
      send(res, { status: 500, body: { error: err instanceof Error ? err.message : 'internal error' } })
    }
  })
}
