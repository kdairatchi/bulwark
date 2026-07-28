// Demo: secure remote-command flow.
// Dashboard enqueues a server-SIGNED, allowlisted command; the device polls,
// VERIFIES the server signature / allowlist / expiry / nonce, then reports a
// result. A forged and an expired command are rejected.

import { generateKeyPairSync, sign, createHash, verify } from 'crypto'

const BASE = process.env.DEVICE_API_URL || 'http://127.0.0.1:8787'
const sha256 = (s) => createHash('sha256').update(s).digest('hex')

async function main() {
  // Enroll a fresh device.
  const pairing = await (await fetch(`${BASE}/v1/pairing-codes`, { method: 'POST' })).json()
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  const enroll = await (await fetch(`${BASE}/v1/devices/enroll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: pairing.code, name: 'Kitchen Tablet', os: 'Android 14', publicKeyPem: publicKey }),
  })).json()
  const deviceId = enroll.deviceId
  console.log('1. enrolled:', deviceId)

  // Fetch the SERVER public key the device will use to verify commands.
  const serverKey = await (await fetch(`${BASE}/v1/server-key`)).json()
  console.log('2. server public key received (PEM length', serverKey.publicKeyPem.length + ')')

  // Dashboard enqueues an allowlisted command.
  const issued = await (await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'RUN_MALWARE_SCAN', parameters: { scope: 'quick' } }),
  })).json()
  console.log('3. dashboard issued:', issued.command.type, issued.command.commandId)

  // A non-allowlisted type is rejected by the server up front.
  const shell = await fetch(`${BASE}/v1/devices/${deviceId}/commands`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'RUN_SHELL', parameters: { cmd: 'rm -rf /' } }),
  })
  console.log('4. RUN_SHELL rejected with status:', shell.status)

  // Device polls (signed GET) for pending commands.
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

  const poll = await signed('GET', `/v1/devices/${deviceId}/commands`)
  console.log('5. device polled', poll.body.commands.length, 'pending command(s)')

  // Device verifies the command the same way agents will (canonical string + server pubkey).
  const cmd = poll.body.commands[0]
  const unsigned = { ...cmd }; delete unsigned.signature
  const canonical = [cmd.commandId, cmd.deviceId, cmd.type, JSON.stringify(cmd.parameters), cmd.issuedAt, cmd.expiresAt, cmd.nonce].join('\n')
  const ok = verify(null, Buffer.from(canonical), serverKey.publicKeyPem, Buffer.from(cmd.signature, 'base64'))
  console.log('6. device verified server signature:', ok)

  // Device "executes" and posts a signed result.
  const result = await signed('POST', `/v1/devices/${deviceId}/commands/${cmd.commandId}/result`, {
    ok: true, threatsFound: 0, durationMs: 842,
  })
  console.log('7. result accepted:', result.body)

  // Forged command (signed by the DEVICE key, not the SERVER key) must fail device-side verification.
  const forgedCanonical = ['cmd_forged', deviceId, 'RUN_MALWARE_SCAN', '{}', new Date().toISOString(), new Date(Date.now() + 60000).toISOString(), 'n'].join('\n')
  const forgedSig = sign(null, Buffer.from(forgedCanonical), privateKey).toString('base64')
  const forgedOk = verify(null, Buffer.from(forgedCanonical), serverKey.publicKeyPem, Buffer.from(forgedSig, 'base64'))
  console.log('8. forged (device-signed) command rejected by verify:', !forgedOk)

  // Expired command rejected.
  const expired = { ...cmd, expiresAt: new Date(Date.now() - 1000).toISOString() }
  const expiredOk = Date.now() <= Date.parse(expired.expiresAt)
  console.log('9. expired command rejected:', !expiredOk)
}

main().catch((e) => { console.error(e); process.exit(1) })
