/**
 * Demo: remote policy sync + emergency isolate against cloud:dev.
 *
 *   npm run cloud:dev
 *   node scripts/policy-isolate-demo.mjs
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
      body: method === 'GET' || method === 'DELETE' ? undefined : rawBody,
    })
    return { status: res.status, body: await res.json() }
  }

  const policy1 = await signed('GET', `/v1/devices/${deviceId}/policy`)
  console.log('2. default policy isolated=', policy1.body.policy.isolated, 'v=', policy1.body.policy.version)

  const put = await fetch(`${BASE}/v1/devices/${deviceId}/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      blockedDomains: ['tracker.malware.test', 'ads.example.invalid'],
      dnsGuardRequired: true,
    }),
  })
  const putBody = await put.json()
  console.log('3. policy updated v=', putBody.policy.version, 'command=', putBody.command.type)

  const isolate = await (await fetch(`${BASE}/v1/devices/${deviceId}/isolate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'demo emergency' }),
  })).json()
  console.log('4. isolated=', isolate.policy.isolated, 'command=', isolate.command.type)

  const poll = await signed('GET', `/v1/devices/${deviceId}/commands`)
  const types = poll.body.commands.map((c) => c.type)
  console.log('5. pending commands:', types.join(', '))
  if (!types.includes('ISOLATE_DEVICE')) throw new Error('expected ISOLATE_DEVICE')
  if (!types.includes('APPLY_POLICY')) throw new Error('expected APPLY_POLICY')

  for (const cmd of poll.body.commands) {
    await signed('POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
      ok: true, applied: true, type: cmd.type, stub: true,
    })
  }
  console.log('6. results posted for', poll.body.commands.length, 'commands')

  const cleared = await fetch(`${BASE}/v1/devices/${deviceId}/isolate`, { method: 'DELETE' })
  const clearedBody = await cleared.json()
  console.log('7. isolation cleared isolated=', clearedBody.policy.isolated)

  const policy2 = await signed('GET', `/v1/devices/${deviceId}/policy`)
  console.log('8. final policy isolated=', policy2.body.policy.isolated, 'v=', policy2.body.policy.version)
  console.log('DONE')
}

main().catch((e) => { console.error(e); process.exit(1) })
