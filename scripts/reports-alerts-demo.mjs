/**
 * Demo: fleet report + computed alerts (KEV, isolation, DNS, breach).
 *
 *   npm run cloud:dev
 *   node scripts/reports-alerts-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

const headers = dashboardAuthHeaders(await fetchDashboardToken(BASE))

async function api(method, path, body, extraHeaders = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { ...headers, ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${JSON.stringify(json)}`)
  return { status: res.status, json }
}

// Bootstrap fixtures: enroll → KEV finding → isolate → dns_blocked → breach monitor
const pairing = await api('POST', '/v1/pairing-codes', {})
const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
})
const enrollRes = await fetch(`${BASE}/v1/devices/enroll`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    code: pairing.json.code,
    name: 'Reports Demo Device',
    os: 'linux',
    publicKeyPem: publicKey,
  }),
})
const enrollJson = await enrollRes.json()
if (!enrollRes.ok) throw new Error(`enroll → ${enrollRes.status} ${JSON.stringify(enrollJson)}`)
const deviceId = enrollJson.deviceId
console.log('enrolled', deviceId)

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
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`signed ${method} ${path} → ${res.status} ${JSON.stringify(json)}`)
  return json
}

await signed('POST', `/v1/devices/${deviceId}/heartbeat`, {})
await signed('POST', `/v1/devices/${deviceId}/findings`, {
  findings: [{
    level: 'likely_affected',
    subjectName: 'DemoBrowser',
    reason: 'CISA KEV CVE-2024-DEMO',
    category: 'kev',
    fixRecommendation: 'Upgrade DemoBrowser',
  }],
})
await api('POST', `/v1/devices/${deviceId}/isolate`, { reason: 'reports-alerts-demo' })
await signed('POST', `/v1/devices/${deviceId}/network-events`, {
  events: [
    { type: 'dns_blocked', subject: 'malware.demo.test', detail: 'blocked by DNS Guard' },
    { type: 'dns_blocked', subject: 'tracker.demo.test', detail: 'blocked by DNS Guard' },
  ],
})

const email = `pwned+reports-${Date.now()}@hibp-test.bulwark.local`
await api('POST', '/v1/breach-monitors', { email })

const report = await api('GET', '/v1/reports')
const summary = report.json.summary
console.log('report summary', summary)
if (summary.deviceCount < 1) throw new Error('expected at least 1 device')
if (summary.openKevTotal < 1) throw new Error('expected open KEV findings')
if (summary.isolatedCount < 1) throw new Error('expected isolated device')
if (summary.dnsBlockedRecent < 1) throw new Error('expected recent dns_blocked')
if (summary.unackedBreaches < 1) throw new Error('expected unacked breaches')

const alerts = await api('GET', '/v1/alerts')
const types = [...new Set(alerts.json.alerts.map((a) => a.type))].sort()
console.log('alert types', types, 'count', alerts.json.count)
for (const t of ['kev_finding', 'isolation', 'dns_blocked', 'breach']) {
  if (!types.includes(t)) throw new Error(`missing alert type ${t}`)
}

const filtered = await api('GET', `/v1/alerts?deviceId=${encodeURIComponent(deviceId)}`)
const filteredTypes = new Set(filtered.json.alerts.map((a) => a.type))
console.log('filtered alert types', [...filteredTypes].sort(), 'count', filtered.json.count)
if (filteredTypes.has('breach')) throw new Error('device filter should exclude breach alerts')
if (!filtered.json.alerts.every((a) => a.deviceId === deviceId)) {
  throw new Error('device filter returned foreign deviceId')
}

console.log('ok')
