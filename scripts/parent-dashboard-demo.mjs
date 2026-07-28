/**
 * Demo: parent dashboard ops — mint code, enroll kid TV, isolate, push policy,
 * ingest dns_blocked events, list via dashboard routes (what Cloud UI uses).
 *
 *   npm run cloud:dev
 *   node scripts/parent-dashboard-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'

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
      name: 'Kids Room TV',
      os: 'Android TV 14',
      publicKeyPem: publicKey,
    }),
  })).json()
  const deviceId = enroll.deviceId
  console.log('2. enrolled:', deviceId)

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
      body: method === 'GET' || method === 'DELETE' ? undefined : rawBody,
    })
    return { status: res.status, body: await res.json() }
  }

  const listed = await (await fetch(`${BASE}/v1/devices`)).json()
  const kid = listed.devices.find((d) => d.id === deviceId)
  if (!kid || kid.isolated !== false) throw new Error('listDevices missing policy summary')
  console.log('3. dashboard list:', kid.name, 'isolated=', kid.isolated, 'v=', kid.policyVersion)

  const put = await (await fetch(`${BASE}/v1/devices/${deviceId}/policy`, {
    method: 'PUT',
    headers: dash,
    body: JSON.stringify({
      blockedDomains: ['tracker.malware.test', 'ads.example.invalid'],
      dnsGuardRequired: true,
    }),
  })).json()
  console.log('4. policy v=', put.policy.version, '→', put.command.type)

  const isolate = await (await fetch(`${BASE}/v1/devices/${deviceId}/isolate`, {
    method: 'POST',
    headers: dash,
    body: JSON.stringify({ reason: 'parent dashboard demo' }),
  })).json()
  console.log('5. isolated=', isolate.policy.isolated, '→', isolate.command.type)

  const after = await (await fetch(`${BASE}/v1/devices`)).json()
  const kid2 = after.devices.find((d) => d.id === deviceId)
  if (!kid2?.isolated) throw new Error('expected isolated=true on listDevices')
  console.log('6. listDevices isolated badge=', kid2.isolated)

  await signed('POST', `/v1/devices/${deviceId}/network-events`, {
    events: [
      { type: 'isolation_enabled', subject: 'device', detail: 'parent isolate' },
      { type: 'dns_blocked', subject: 'tracker.malware.test', detail: 'blocked by policy' },
      { type: 'dns_blocked', subject: 'ads.example.invalid', detail: 'blocked by policy' },
    ],
  })

  const events = await (await fetch(`${BASE}/v1/network-events?deviceId=${encodeURIComponent(deviceId)}`)).json()
  console.log('7. network events:', events.count)
  if (events.count < 3) throw new Error('expected >=3 events')
  for (const e of events.events) {
    console.log('   -', e.type, e.subject)
  }

  const cleared = await (await fetch(`${BASE}/v1/devices/${deviceId}/isolate`, { method: 'DELETE', headers: dash })).json()
  console.log('8. cleared isolation=', cleared.policy.isolated, '→', cleared.command.type)
  console.log('OK parent dashboard loop')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
