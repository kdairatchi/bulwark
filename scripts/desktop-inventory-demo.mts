/**
 * Demo: desktop inventory + findings → control plane → parent listFindings.
 *
 *   npm run cloud:dev
 *   npx tsx scripts/desktop-inventory-demo.mts
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import { collectDesktopInventory } from '../src/main/services/desktop-inventory'
import type { InstalledApp } from '../src/main/platform/types'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

async function dashAuth() {
  const boot = await (await fetch(`${BASE}/v1/dashboard-bootstrap`)).json() as { token: string }
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${boot.token}` }
}

async function main() {
  const dash = await dashAuth()
  const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST', headers: dash, body: '{}' })).json() as { code: string }
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  const enroll = await (await fetch(`${BASE}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code: pairing.code,
      name: 'Family PC',
      os: 'linux',
      publicKeyPem: publicKey,
    }),
  })).json() as { deviceId: string }
  const deviceId = enroll.deviceId
  console.log('1. enrolled:', deviceId)

  async function signed(method: string, path: string, bodyObj?: unknown) {
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
    return { status: res.status, body: await res.json() as Record<string, unknown> }
  }

  const fakeApps: InstalledApp[] = [
    { name: 'Firefox', version: '128', publisher: 'Mozilla', installDate: '', sizeKb: 1000 },
    { name: 'Mystery Tool', version: '1', publisher: '', installDate: '', sizeKb: 10 },
    { name: 'Game Crack Pack', version: '1', publisher: 'Shady LLC', installDate: '', sizeKb: 50 },
  ]
  const payload = await collectDesktopInventory({
    loadApps: async () => fakeApps,
    platform: 'linux',
    hostname: 'family-pc',
  })
  console.log('2. inventory apps=', payload.count, 'findings=', payload.findings.length)

  await signed('POST', `/v1/devices/${deviceId}/inventory`, {
    apps: payload.apps,
    count: payload.count,
  })
  const findingsRes = await signed('POST', `/v1/devices/${deviceId}/findings`, {
    findings: payload.findings,
  })
  console.log('3. findings accepted=', (findingsRes.body as { accepted: number }).accepted)

  const listed = await (await fetch(`${BASE}/v1/devices`, { headers: dash })).json() as {
    devices: Array<{ id: string; inventoryCount: number; findingsCount: number }>
  }
  const dev = listed.devices.find((d) => d.id === deviceId)!
  console.log('4. dashboard counts apps=', dev.inventoryCount, 'findings=', dev.findingsCount)
  if (dev.inventoryCount < 3) throw new Error('expected inventoryCount >= 3')
  if (dev.findingsCount < 1) throw new Error('expected findingsCount >= 1')

  const findings = await (await fetch(`${BASE}/v1/findings?deviceId=${deviceId}`, { headers: dash })).json() as {
    findings: Array<{ subjectName: string; reason: string }>
    count: number
  }
  console.log('5. parent findings feed:', findings.count)
  for (const f of findings.findings) console.log('   -', f.subjectName, f.reason)

  const cmd = await (await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
    method: 'POST',
    headers: dash,
    body: JSON.stringify({ type: 'REQUEST_INVENTORY', parameters: {} }),
  })).json() as { command: { type: string } }
  console.log('6. queued command:', cmd.command.type)
  if (cmd.command.type !== 'REQUEST_INVENTORY') throw new Error('expected REQUEST_INVENTORY')

  console.log('OK desktop inventory → parent findings loop')
  process.exit(0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
