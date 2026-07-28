// Demo device client for the Bulwark device API.
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'
// Simulates a desktop/TV agent: get a pairing code, generate a per-device
// Ed25519 key pair, enroll, then send SIGNED heartbeat / inventory / findings.
// Finally reads back the dashboard views. No shared API key anywhere.

import { generateKeyPairSync, sign, createHash } from 'crypto'

const BASE = process.env.DEVICE_API_URL || 'http://127.0.0.1:8787'

const sha256 = (s) => createHash('sha256').update(s).digest('hex')

async function main() {
  const token = process.env.DASHBOARD_TOKEN || await fetchDashboardToken(BASE)
  const dash = dashboardAuthHeaders(token)
  // 1. Dashboard issues a short-lived pairing code.
  const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST', headers: dash, body: '{}' })).json()
  console.log('1. pairing code:', pairing.code, '(expires', pairing.expiresAt + ')')

  // 2. Device generates its own key pair and enrolls with the code.
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  const enroll = await (await fetch(`${BASE}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: pairing.code, name: 'Living Room TV', os: 'Android TV 14', publicKeyPem: publicKey }),
  })).json()
  const deviceId = enroll.deviceId
  console.log('2. enrolled:', deviceId)

  // Signed request helper: sign METHOD\npath\ntimestamp\nsha256(body).
  async function signedPost(path, bodyObj) {
    const rawBody = JSON.stringify(bodyObj)
    const timestamp = new Date().toISOString()
    const message = `POST\n${path}\n${timestamp}\n${sha256(rawBody)}`
    const signature = sign(null, Buffer.from(message), privateKey).toString('base64')
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': deviceId,
        'X-Timestamp': timestamp,
        'X-Signature': signature,
      },
      body: rawBody,
    })
    return { status: res.status, body: await res.json() }
  }

  // 3. Signed telemetry.
  console.log('3. heartbeat:', (await signedPost(`/v1/devices/${deviceId}/heartbeat`, {})).body)
  console.log('   inventory:', (await signedPost(`/v1/devices/${deviceId}/inventory`, {
    items: [{ pkg: 'com.example.player' }, { pkg: 'com.android.chrome' }, { pkg: 'com.sideload.unknown' }],
  })).body)
  console.log('   findings :', (await signedPost(`/v1/devices/${deviceId}/findings`, {
    findings: [
      { level: 'high', subjectName: 'com.sideload.unknown', reason: 'sideloaded_unknown_source' },
      { level: 'medium', subjectName: 'com.example.player', reason: 'requests_admin' },
    ],
  })).body)

  // 4. A tampered/unsigned request must be rejected.
  const unsigned = await fetch(`${BASE}/v1/devices/${deviceId}/heartbeat`, { method: 'POST', body: '{}' })
  console.log('4. unsigned heartbeat rejected with status:', unsigned.status)

  // 5. Dashboard views.
  console.log('5. GET /v1/devices  ->', JSON.stringify(await (await fetch(`${BASE}/v1/devices`)).json(), null, 2))
  console.log('   GET /v1/findings ->', JSON.stringify(await (await fetch(`${BASE}/v1/findings`)).json(), null, 2))
}

main().catch((e) => { console.error(e); process.exit(1) })
