/**
 * Persist the Bulwrk device-API identity (Ed25519 key pair + device id).
 * Private key is encrypted at rest with Electron safeStorage when available
 * (same pattern as the legacy cloud API key). Separate from settings.cloud.apiKey.
 */

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, unlinkSync } from 'fs'
import { join } from 'path'
import { app, safeStorage } from 'electron'

const ENCRYPTED_KEY_PREFIX = 'v1:enc:'
const FILE_NAME = 'device-api-identity.json'

export interface DeviceIdentity {
  deviceId: string
  name: string
  publicKeyPem: string
  privateKeyPem: string
  serverPublicKeyPem: string
  baseUrl: string
  enrolledAt: string
}

interface StoredIdentity {
  deviceId: string
  name: string
  publicKeyPem: string
  /** Encrypted or plaintext private key */
  privateKeyPem: string
  serverPublicKeyPem: string
  baseUrl: string
  enrolledAt: string
}

function identityPath(): string {
  return join(app.getPath('userData'), FILE_NAME)
}

function encryptSecret(plain: string): string {
  if (!plain) return ''
  try {
    if (safeStorage.isEncryptionAvailable()) {
      return ENCRYPTED_KEY_PREFIX + safeStorage.encryptString(plain).toString('base64')
    }
  } catch { /* fall through */ }
  return plain
}

function decryptSecret(stored: string): string {
  if (!stored) return ''
  if (stored.startsWith(ENCRYPTED_KEY_PREFIX)) {
    try {
      if (!safeStorage.isEncryptionAvailable()) return ''
      const buf = Buffer.from(stored.slice(ENCRYPTED_KEY_PREFIX.length), 'base64')
      return safeStorage.decryptString(buf)
    } catch {
      return ''
    }
  }
  return stored
}

export function loadDeviceIdentity(): DeviceIdentity | null {
  try {
    const p = identityPath()
    if (!existsSync(p)) return null
    const raw = JSON.parse(readFileSync(p, 'utf-8')) as Partial<StoredIdentity>
    if (
      typeof raw.deviceId !== 'string' ||
      typeof raw.publicKeyPem !== 'string' ||
      typeof raw.privateKeyPem !== 'string' ||
      typeof raw.serverPublicKeyPem !== 'string' ||
      typeof raw.baseUrl !== 'string'
    ) {
      return null
    }
    const privateKeyPem = decryptSecret(raw.privateKeyPem)
    if (!privateKeyPem.includes('BEGIN PRIVATE KEY')) return null
    return {
      deviceId: raw.deviceId,
      name: typeof raw.name === 'string' ? raw.name : 'Device',
      publicKeyPem: raw.publicKeyPem,
      privateKeyPem,
      serverPublicKeyPem: raw.serverPublicKeyPem,
      baseUrl: raw.baseUrl,
      enrolledAt: typeof raw.enrolledAt === 'string' ? raw.enrolledAt : new Date().toISOString(),
    }
  } catch {
    return null
  }
}

export function saveDeviceIdentity(identity: DeviceIdentity): void {
  const dir = app.getPath('userData')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const stored: StoredIdentity = {
    ...identity,
    privateKeyPem: encryptSecret(identity.privateKeyPem),
  }
  const p = identityPath()
  const tmp = p + '.tmp'
  writeFileSync(tmp, JSON.stringify(stored, null, 2), 'utf-8')
  renameSync(tmp, p)
}

export function clearDeviceIdentity(): void {
  const p = identityPath()
  try {
    if (existsSync(p)) unlinkSync(p)
  } catch { /* ignore */ }
}
