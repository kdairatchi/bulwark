/**
 * Demo: parent requests a health scan → agent tick executes non-stub scan → findings land.
 *
 *   npm run cloud:dev
 *   node scripts/remote-scan-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

function deviceKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    privateKey,
  }
}

async function signed(privateKey, deviceId, method, path, bodyObj) {
  const body = bodyObj === undefined ? '' : JSON.stringify(bodyObj)
  const ts = new Date().toISOString()
  const msg = `${method}\n${path}\n${ts}\n${sha256(body)}`
  const signature = sign(null, Buffer.from(msg), privateKey).toString('base64')
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Device-Id': deviceId,
      'X-Timestamp': ts,
      'X-Signature': signature,
    },
    body: method === 'GET' || method === 'HEAD' ? undefined : body,
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${JSON.stringify(json)}`)
  return json
}

const headers = dashboardAuthHeaders(await fetchDashboardToken(BASE))
const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST', headers, body: '{}' })).json()
const keys = deviceKeys()
const enrolled = await (await fetch(`${BASE}/v1/devices/enroll`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: pairing.code,
    name: 'Scan Demo Laptop',
    publicKeyPem: keys.publicKeyPem,
    os: 'linux',
  }),
})).json()
const deviceId = enrolled.deviceId
console.log('enrolled', deviceId)

const scan = await (await fetch(`${BASE}/v1/devices/${deviceId}/scan`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ kind: 'health' }),
})).json()
console.log('queued', scan.command?.type, scan.command?.commandId)

// Device poll + fake execute with findings (mirrors desktop agent path).
const polled = await signed(keys.privateKey, deviceId, 'GET', `/v1/devices/${deviceId}/commands`)
const cmd = polled.commands?.[0]
if (!cmd) throw new Error('no pending command')
await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
  ok: true,
  stub: false,
  type: cmd.type,
  findings: 2,
  postureScore: 72,
})
await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/findings`, {
  findings: [
    { level: 'potential_match', subjectName: 'Mystery App', reason: 'unknown_publisher' },
    { level: 'safe', subjectName: 'device_posture', reason: 'posture_score_72' },
  ],
})

const listed = await (await fetch(`${BASE}/v1/findings?deviceId=${encodeURIComponent(deviceId)}`, { headers })).json()
console.log('findings', listed.count, listed.findings?.map((f) => f.reason))
console.log('ok')
