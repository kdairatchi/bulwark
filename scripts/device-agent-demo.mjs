/**
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'
 * End-to-end demo of the desktop agent flow against a running device API:
 *   1. Create pairing code (dashboard)
 *   2. Enroll with a fresh Ed25519 key pair (device)
 *   3. Issue RUN_MALWARE_SCAN (dashboard)
 *   4. Device polls, verifies server signature, executes stub, posts result
 *
 * Requires: npm run cloud:dev
 * Run:      node scripts/device-agent-demo.mjs
 */

import { generateKeyPairSync, sign, createHash, verify } from 'crypto'
import { hostname, platform, release } from 'os'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

async function main() {
  const token = process.env.DASHBOARD_TOKEN || await fetchDashboardToken(BASE)
  const dash = dashboardAuthHeaders(token)
  const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST', headers: dash, body: '{}' })).json()
  console.log('1. pairing code:', pairing.code)

  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

  const enroll = await (await fetch(`${BASE}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code: pairing.code,
      name: `Agent Demo (${hostname()})`,
      os: `${platform()} ${release()}`,
      publicKeyPem: publicKey,
    }),
  })).json()
  const deviceId = enroll.deviceId
  console.log('2. enrolled:', deviceId)

  const serverKey = await (await fetch(`${BASE}/v1/server-key`)).json()
  console.log('3. cached server public key')

  const issued = await (await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
    method: 'POST',
    headers: dash,
    body: JSON.stringify({ type: 'RUN_MALWARE_SCAN', parameters: { scope: 'quick' } }),
  })).json()
  console.log('4. dashboard issued:', issued.command.type, issued.command.commandId)

  async function signed(method, path, bodyObj) {
    const rawBody = bodyObj === undefined ? '' : JSON.stringify(bodyObj)
    const timestamp = new Date().toISOString()
    const message = `${method}\n${path}\n${timestamp}\n${sha256(rawBody)}`
    const signature = sign(null, Buffer.from(message), privateKey).toString('base64')
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': deviceId,
        'X-Timestamp': timestamp,
        'X-Signature': signature,
      },
      body: method === 'GET' ? undefined : rawBody,
    })
    return { status: res.status, body: await res.json() }
  }

  await signed('POST', `/v1/devices/${deviceId}/heartbeat`, {})
  console.log('5. heartbeat ok')

  const poll = await signed('GET', `/v1/devices/${deviceId}/commands`)
  const cmd = poll.body.commands[0]
  console.log('6. polled command:', cmd.type)

  const canonical = [cmd.commandId, cmd.deviceId, cmd.type, JSON.stringify(cmd.parameters), cmd.issuedAt, cmd.expiresAt, cmd.nonce].join('\n')
  const sigOk = verify(null, Buffer.from(canonical), serverKey.publicKeyPem, Buffer.from(cmd.signature, 'base64'))
  if (!sigOk) throw new Error('server signature verification failed')
  console.log('7. verified server signature')

  // Stub executor (same shape as defaultCommandExecutor)
  const stubResult = { ok: true, stub: true, type: cmd.type, threatsFound: 0, commandId: cmd.commandId }
  const reported = await signed('POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, stubResult)
  console.log('8. result accepted:', reported.body)
  console.log('DONE')
}

main().catch((e) => { console.error(e); process.exit(1) })
