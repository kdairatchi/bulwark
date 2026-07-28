// Per-device cryptography for the cloud device API.
//
// Each device generates its own Ed25519 key pair at enrollment; the cloud stores
// only the PUBLIC key. Authenticated requests are signed with the device's
// private key over a canonical string, so there is no shared API key to leak
// (see docs/threat-model.md and docs/api/device-and-dashboard-api.md).

import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify, createHash } from 'crypto'

export interface DeviceKeyPair {
  publicKeyPem: string
  privateKeyPem: string
}

export function generateDeviceKeyPair(): DeviceKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKeyPem: publicKey as string, privateKeyPem: privateKey as string }
}

export function sha256Hex(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

/**
 * The exact string a device signs / the server verifies. Binding method, path,
 * timestamp, and a body hash prevents replay across endpoints and tampering.
 */
export function canonicalRequest(method: string, path: string, timestamp: string, bodyHash: string): string {
  return `${method.toUpperCase()}\n${path}\n${timestamp}\n${bodyHash}`
}

export function signMessage(privateKeyPem: string, message: string): string {
  return nodeSign(null, Buffer.from(message), privateKeyPem).toString('base64')
}

export function verifyMessage(publicKeyPem: string, message: string, signatureB64: string): boolean {
  try {
    return nodeVerify(null, Buffer.from(message), publicKeyPem, Buffer.from(signatureB64, 'base64'))
  } catch {
    return false
  }
}
