/**
 * Demo: category persistence, open-finding dedupe, KEV-weighted score, review recovery.
 *
 *   npm run cloud:dev
 *   node scripts/finding-review-demo.mjs
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
    name: 'Review Demo Laptop',
    publicKeyPem: keys.publicKeyPem,
    os: 'linux',
  }),
})).json()
const deviceId = enrolled.deviceId

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
      subjectName: 'Mystery',
      reason: 'unknown_publisher',
      category: 'publisher',
    },
  ],
})

// Re-submit KEV with EPSS tag — must dedupe, not double-count.
await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/findings`, {
  findings: [
    {
      level: 'likely_affected',
      subjectName: 'CVE-2023-38545',
      reason: 'kev_version_match_<8.4.0:curl@7.88.1:epss=0.78',
      category: 'kev',
    },
  ],
})

const listed = await (await fetch(`${BASE}/v1/findings?deviceId=${encodeURIComponent(deviceId)}`, { headers })).json()
console.log('findings', listed.count, listed.findings.map((f) => `${f.category}:${f.subjectName}`))
if (listed.count !== 2) throw new Error(`expected 2 findings after dedupe, got ${listed.count}`)
const kev = listed.findings.find((f) => f.category === 'kev')
if (!kev?.reason.includes('epss=')) throw new Error('expected refreshed KEV reason')

const before = await (await fetch(`${BASE}/v1/devices`, { headers })).json()
const d0 = before.devices.find((d) => d.id === deviceId)
console.log('before', { securityScore: d0.securityScore, openFindingsCount: d0.openFindingsCount })

const reviewed = await (await fetch(`${BASE}/v1/findings/${encodeURIComponent(kev.id)}/review`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ status: 'false_positive', note: 'demo dismiss kev' }),
})).json()
console.log('reviewed', reviewed.finding.status, 'score', reviewed.securityScore, 'open', reviewed.openFindingsCount)

const after = await (await fetch(`${BASE}/v1/devices`, { headers })).json()
const d1 = after.devices.find((d) => d.id === deviceId)
console.log('after', { securityScore: d1.securityScore, openFindingsCount: d1.openFindingsCount })
if (!(d1.securityScore > d0.securityScore)) throw new Error('expected score to improve after review')
console.log('ok')
