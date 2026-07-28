/**
 * Demo: parent queues vulnerability scan → agent reports KEV CVE findings.
 *
 *   npm run cloud:dev
 *   node scripts/kev-scan-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

function deviceKeys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
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
    name: 'KEV Demo Laptop',
    publicKeyPem: keys.publicKeyPem,
    os: 'linux',
  }),
})).json()
const deviceId = enrolled.deviceId
console.log('enrolled', deviceId)

const scan = await (await fetch(`${BASE}/v1/devices/${deviceId}/scan`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ kind: 'vulnerability' }),
})).json()
console.log('queued', scan.command?.type)

const polled = await signed(keys.privateKey, deviceId, 'GET', `/v1/devices/${deviceId}/commands`)
const cmd = polled.commands?.[0]
if (!cmd) throw new Error('no pending command')

await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
  ok: true,
  stub: false,
  type: 'RUN_VULNERABILITY_SCAN',
  scope: 'kev_posture_technique',
  findings: 2,
  threatsFound: 2,
  note: 'Offline KEV match — full NVD/EPSS Phase 5 still incomplete',
})

await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/findings`, {
  findings: [
    {
      level: 'likely_affected',
      subjectName: 'CVE-2023-38545',
      reason: 'kev_version_match_<8.4.0:curl@7.88.1',
      category: 'kev',
    },
    {
      level: 'potential_match',
      subjectName: 'CVE-2024-1709',
      reason: 'kev_product_match:ScreenConnect@22.0:ransomware',
      category: 'kev',
    },
  ],
})

const listed = await (await fetch(`${BASE}/v1/findings?deviceId=${encodeURIComponent(deviceId)}`, { headers })).json()
console.log('findings', listed.findings?.map((f) => `${f.subjectName} (${f.category || f.reason})`))
console.log('ok')
