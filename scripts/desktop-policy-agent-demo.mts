/**
 * Demo: desktop policy enforcer + device API — isolate → loopback DoT sinkhole
 * → flush dns_blocked events. Does NOT rewrite system DNS.
 *
 *   npm run cloud:dev
 *   npx tsx scripts/desktop-policy-agent-demo.mts
 */

import { generateKeyPairSync, sign, createHash } from 'crypto'
import dgram from 'dgram'
import { devicePolicyEnforcer, parseRemotePolicy } from '../src/main/services/device-policy-enforcer'
import { dnsResolver } from '../src/main/services/dns-resolver'

const BASE = (process.env.DEVICE_API_URL || 'http://127.0.0.1:8787').replace(/\/+$/, '')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

async function dashAuth() {
  const boot = await (await fetch(`${BASE}/v1/dashboard-bootstrap`)).json() as { token: string }
  return { 'Content-Type': 'application/json', Authorization: `Bearer ${boot.token}` }
}

function query(name: string, qtype = 1): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x4242, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]))
  const qname = Buffer.concat([...labels, Buffer.from([0])])
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(1, 2)
  return Buffer.concat([header, qname, tail])
}

function udpQuery(port: number, msg: Buffer, timeoutMs = 2000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    const timer = setTimeout(() => { sock.close(); reject(new Error('timeout')) }, timeoutMs)
    sock.on('message', (res) => { clearTimeout(timer); sock.close(); resolve(res) })
    sock.on('error', (e) => { clearTimeout(timer); sock.close(); reject(e) })
    sock.send(msg, port, '127.0.0.1')
  })
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
      name: 'Parent Laptop',
      os: 'linux',
      publicKeyPem: publicKey,
    }),
  })).json() as { deviceId: string }
  const deviceId = enroll.deviceId
  console.log('1. enrolled desktop:', deviceId)

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

  await fetch(`${BASE}/v1/devices/${deviceId}/policy`, {
    method: 'PUT',
    headers: dash,
    body: JSON.stringify({
      blockedDomains: ['tracker.malware.test'],
      dnsGuardRequired: true,
      isolationAllowlist: ['googleapis.com', 'cloudflare.com'],
    }),
  })
  await fetch(`${BASE}/v1/devices/${deviceId}/isolate`, {
    method: 'POST',
    headers: dash,
    body: JSON.stringify({ reason: 'desktop agent demo' }),
  })

  const pol = await signed('GET', `/v1/devices/${deviceId}/policy`)
  const policyBody = (pol.body as { policy: unknown }).policy
  console.log('2. policy isolated=', (policyBody as { isolated: boolean }).isolated)

  devicePolicyEnforcer.setLocalBlocklistProvider(() => [])
  devicePolicyEnforcer.drainEvents()
  // Ephemeral port so this demo does not clash with Electron Network Guard on :5353.
  const applied = await devicePolicyEnforcer.applyRemotePolicy(
    parseRemotePolicy(policyBody),
    { port: 0 as unknown as number },
  )
  console.log('3. applied locally:', applied.mode, 'domains=', applied.domainCount, 'addr=', applied.address)
  const address = typeof applied.address === 'string' ? applied.address : null
  if (!address) throw new Error('resolver not running')
  const port = Number(address.split(':')[1])
  const blocked = await udpQuery(port, query('evil.not-on-allowlist.test'))
  const sink = [...blocked.subarray(blocked.length - 4)]
  console.log('4. isolation sinkhole=', sink.join('.'))
  if (sink.some((b) => b !== 0)) throw new Error('expected 0.0.0.0 sinkhole')

  const events = devicePolicyEnforcer.drainEvents()
  console.log('5. local events queued:', events.map((e) => e.type).join(', '))
  if (!events.some((e) => e.type === 'dns_blocked')) throw new Error('expected dns_blocked')

  const flush = await signed('POST', `/v1/devices/${deviceId}/network-events`, { events })
  console.log('6. flushed to cloud accepted=', (flush.body as { accepted: number }).accepted)

  const listed = await (await fetch(`${BASE}/v1/network-events?deviceId=${deviceId}`)).json() as { count: number }
  console.log('7. cloud events:', listed.count)
  if (listed.count < 1) throw new Error('expected cloud events')

  await dnsResolver.stop()
  dnsResolver.setOnBlocked(null)
  dnsResolver.setFilterMode('blocklist', [])
  console.log('OK desktop policy agent loop (loopback only — system DNS unchanged)')
  process.exit(0)
}

main().catch(async (err) => {
  console.error(err)
  try {
    await dnsResolver.stop()
    dnsResolver.setOnBlocked(null)
  } catch { /* ignore */ }
  process.exit(1)
})
