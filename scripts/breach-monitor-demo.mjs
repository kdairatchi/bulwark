/**
 * Demo: email breach monitors (stub HIBP — no API key required).
 *
 *   npm run cloud:dev
 *   node scripts/breach-monitor-demo.mjs
 */

import { fetchDashboardToken, dashboardAuthHeaders } from './dashboard-auth.mjs'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const headers = dashboardAuthHeaders(await fetchDashboardToken(BASE))

async function api(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status} ${JSON.stringify(json)}`)
  return { status: res.status, json }
}

// Clean email — stub returns no breaches.
const clean = await api('POST', '/v1/breach-monitors', { email: 'safe@example.com' })
const cleanEntry = clean.json.emails?.find((e) => e.email === 'safe@example.com')
console.log('clean', { status: clean.status, source: clean.json.source, breaches: cleanEntry?.breaches?.length })
if (!cleanEntry || cleanEntry.breaches.length !== 0) {
  throw new Error('expected no breaches for safe@example.com')
}

// Pwned stub trigger — Adobe + LinkedIn fixtures.
const pwned = await api('POST', '/v1/breach-monitors', { email: 'pwned@hibp-test.bulwrk.local' })
console.log('pwned', {
  status: pwned.status,
  source: pwned.json.source,
  usage: pwned.json.usage,
  breaches: pwned.json.emails?.find((e) => e.email.includes('pwned'))?.breaches?.map((b) => b.name),
})
const pwnedEntry = pwned.json.emails.find((e) => e.email === 'pwned@hibp-test.bulwrk.local')
if (!pwnedEntry || pwnedEntry.breaches.length < 1) {
  throw new Error('expected stub breaches for pwned@hibp-test.bulwrk.local')
}

const listed = await api('GET', '/v1/breach-monitors')
console.log('list', { usage: listed.json.usage, emails: listed.json.emails.map((e) => e.email) })
if (listed.json.usage < 2) throw new Error('expected at least 2 monitors')

const breachId = pwnedEntry.breaches[0].id
const ack = await api('POST', '/v1/breach-monitors/acknowledge', { breachIds: [breachId] })
console.log('ack', { acknowledged: ack.json.acknowledged })
if (ack.json.acknowledged !== 1) throw new Error('expected 1 acknowledged')

const refreshed = await api('POST', '/v1/breach-monitors/refresh', { email: 'pwned@hibp-test.bulwrk.local' })
const after = refreshed.json.emails.find((e) => e.email === 'pwned@hibp-test.bulwrk.local')
const stillAcked = after?.breaches.find((b) => b.id === breachId)
console.log('refresh', { source: refreshed.json.source, stillAcked: !!stillAcked?.acknowledgedAt })
if (!stillAcked?.acknowledgedAt) throw new Error('expected acknowledgedAt preserved after refresh')

const deleted = await api('DELETE', `/v1/breach-monitors/${encodeURIComponent('safe@example.com')}`)
console.log('delete clean', { usage: deleted.json.usage })
if (deleted.json.emails.some((e) => e.email === 'safe@example.com')) {
  throw new Error('safe@example.com should be removed')
}

console.log('ok')
