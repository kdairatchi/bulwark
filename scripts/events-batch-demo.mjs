/**
 * Demo: deeper posture findings + network-events batch ingest.
 *
 *   npm run cloud:dev
 *   node scripts/events-batch-demo.mjs
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

async function main() {
  const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST' })).json()
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  const enroll = await (await fetch(`${BASE}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code: pairing.code,
      name: 'Living Room TV',
      os: 'Android TV 14',
      publicKeyPem: publicKey,
    }),
  })).json()
  const deviceId = enroll.deviceId
  console.log('1. enrolled:', deviceId)

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

  const inventory = await signed('POST', `/v1/devices/${deviceId}/inventory`, {
    count: 2,
    apps: [
      {
        packageName: 'com.example.sideload',
        sideloaded: true,
        debuggable: true,
        targetSdk: 26,
        exportedActivities: 3,
        apkSha256: 'aa'.repeat(32),
        certSha256: 'bb'.repeat(32),
      },
      { packageName: 'com.netflix.ninja', sideloaded: false, targetSdk: 34 },
    ],
  })
  console.log('2. inventory accepted:', inventory.body)

  const findings = await signed('POST', `/v1/devices/${deviceId}/findings`, {
    findings: [
      { level: 'confirmed_affected', subjectName: 'com.example.sideload', reason: 'debuggable sideload' },
      { level: 'likely_affected', subjectName: 'com.example.sideload', reason: 'exported attack surface' },
    ],
  })
  console.log('3. findings accepted:', findings.body)

  const events = await signed('POST', `/v1/devices/${deviceId}/network-events`, {
    events: [
      { type: 'dns_blocked', subject: 'tracker.malware.test', detail: 'DNS query blocked by local guard' },
      { type: 'dns_blocked', subject: 'ads.example.invalid', detail: 'DNS query blocked by local guard' },
      { type: 'isolation_enabled', subject: 'device', detail: 'Emergency isolation enabled' },
      { type: 'finding', subject: 'com.example.sideload', detail: 'debuggable', metadata: { level: 'confirmed_affected' } },
    ],
  })
  console.log('4. network-events accepted:', events.body)

  const listed = await (await fetch(`${BASE}/v1/network-events?deviceId=${deviceId}`)).json()
  console.log('5. dashboard sees', listed.count, 'events; types=', listed.events.map((e) => e.type).join(','))
  if (listed.count < 4) throw new Error('expected >= 4 events')
  console.log('DONE')
}

main().catch((e) => { console.error(e); process.exit(1) })
