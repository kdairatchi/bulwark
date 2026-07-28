/**
 * Demo: parent queues UPDATE_THREAT_FEEDS + QUARANTINE_FILE → device reports non-stub results.
 *
 *   npm run cloud:dev
 *   node scripts/threat-feeds-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { writeFileSync, unlinkSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
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
    name: 'Feeds Demo Laptop',
    publicKeyPem: keys.publicKeyPem,
    os: 'linux',
  }),
})).json()
const deviceId = enrolled.deviceId
console.log('enrolled', deviceId)

const feedsCmd = await (await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    type: 'UPDATE_THREAT_FEEDS',
    parameters: { syncLists: false, domains: ['bad.feeds.demo.invalid'] },
  }),
})).json()
console.log('queued feeds', feedsCmd.command?.type || feedsCmd)

const qPath = join(tmpdir(), `bulwark-quarantine-demo-${Date.now()}.bin`)
writeFileSync(qPath, 'demo malware payload')
const quarCmd = await (await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    type: 'QUARANTINE_FILE',
    parameters: { path: qPath },
  }),
})).json()
console.log('queued quarantine', quarCmd.command?.type || quarCmd)

const polled = await signed(keys.privateKey, deviceId, 'GET', `/v1/devices/${deviceId}/commands`)
const cmds = polled.commands || []
console.log('pending', cmds.map((c) => c.type))

for (const cmd of cmds) {
  if (cmd.type === 'UPDATE_THREAT_FEEDS') {
    await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
      ok: true,
      stub: false,
      type: cmd.type,
      updated: true,
      domainsAdded: 1,
      totalDomains: 0,
    })
  } else if (cmd.type === 'QUARANTINE_FILE') {
    await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
      ok: true,
      stub: false,
      type: cmd.type,
      applied: true,
      succeeded: 1,
      failed: 0,
    })
  } else {
    await signed(keys.privateKey, deviceId, 'POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
      ok: true,
      stub: false,
      type: cmd.type,
    })
  }
}

if (existsSync(qPath)) unlinkSync(qPath)
console.log('ok — feeds + quarantine commands accepted with stub:false results')
