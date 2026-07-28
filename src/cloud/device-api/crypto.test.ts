import { describe, it, expect } from 'vitest'
import { generateDeviceKeyPair, signMessage, verifyMessage, canonicalRequest, sha256Hex } from './crypto'

describe('device-api crypto', () => {
  it('generates an Ed25519 key pair (PEM)', () => {
    const kp = generateDeviceKeyPair()
    expect(kp.publicKeyPem).toContain('BEGIN PUBLIC KEY')
    expect(kp.privateKeyPem).toContain('BEGIN PRIVATE KEY')
  })

  it('signs and verifies a message round-trip', () => {
    const kp = generateDeviceKeyPair()
    const msg = canonicalRequest('POST', '/v1/devices/x/heartbeat', '2026-07-28T00:00:00Z', sha256Hex('{}'))
    const sig = signMessage(kp.privateKeyPem, msg)
    expect(verifyMessage(kp.publicKeyPem, msg, sig)).toBe(true)
  })

  it('rejects a tampered message', () => {
    const kp = generateDeviceKeyPair()
    const sig = signMessage(kp.privateKeyPem, 'original')
    expect(verifyMessage(kp.publicKeyPem, 'tampered', sig)).toBe(false)
  })

  it('rejects a signature from a different key', () => {
    const a = generateDeviceKeyPair()
    const b = generateDeviceKeyPair()
    const sig = signMessage(a.privateKeyPem, 'msg')
    expect(verifyMessage(b.publicKeyPem, 'msg', sig)).toBe(false)
  })

  it('verify returns false on malformed input instead of throwing', () => {
    expect(verifyMessage('not-a-key', 'msg', 'not-b64')).toBe(false)
  })

  it('canonicalRequest binds method, path, timestamp, and body hash', () => {
    expect(canonicalRequest('post', '/p', 'T', 'H')).toBe('POST\n/p\nT\nH')
  })
})
