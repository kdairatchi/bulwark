import { describe, it, expect, vi } from 'vitest'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp' },
  safeStorage: { isEncryptionAvailable: () => false, encryptString: (s: string) => Buffer.from(s), decryptString: (b: Buffer) => b.toString() },
}))

import { generateDeviceKeyPair, signMessage } from '../../cloud/device-api/crypto'
import { signCommand, type CommandEnvelope } from '../../cloud/device-api/commands'
import {
  processVerifiedCommand,
  defaultCommandExecutor,
} from './device-command-agent'
import { buildSignedHeaders } from './device-api-client'

describe('buildSignedHeaders', () => {
  it('produces verifiable device auth headers', () => {
    const keys = generateDeviceKeyPair()
    const headers = buildSignedHeaders(
      keys.privateKeyPem,
      'dev_1',
      'GET',
      '/v1/devices/dev_1/commands',
      '',
      new Date('2026-01-01T00:00:00.000Z'),
    )
    expect(headers['X-Device-Id']).toBe('dev_1')
    expect(headers['X-Timestamp']).toBe('2026-01-01T00:00:00.000Z')
    expect(headers['X-Signature']).toMatch(/^[A-Za-z0-9+/=]+$/)
  })
})

describe('processVerifiedCommand', () => {
  const server = generateDeviceKeyPair()
  const deviceId = 'dev_abc'

  function makeCmd(overrides: Partial<CommandEnvelope> = {}): CommandEnvelope {
    const unsigned = {
      commandId: 'cmd_1',
      deviceId,
      type: 'RUN_MALWARE_SCAN' as const,
      parameters: { scope: 'quick' },
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      nonce: 'nonce-1',
      ...overrides,
    }
    // If caller overrode signature-affecting fields without signature, resign.
    if (!overrides.signature) {
      return signCommand(server.privateKeyPem, {
        commandId: unsigned.commandId,
        deviceId: unsigned.deviceId,
        type: unsigned.type,
        parameters: unsigned.parameters,
        issuedAt: unsigned.issuedAt,
        expiresAt: unsigned.expiresAt,
        nonce: unsigned.nonce,
      })
    }
    return unsigned as CommandEnvelope
  }

  it('accepts a valid server-signed allowlisted command and executes it', async () => {
    const seen = new Set<string>()
    const execute = vi.fn(async () => ({ ok: true, threatsFound: 0 }))
    const result = await processVerifiedCommand({
      serverPublicKeyPem: server.publicKeyPem,
      deviceId,
      cmd: makeCmd(),
      seenNonces: seen,
      now: Date.now(),
      execute,
    })
    expect(result.accepted).toBe(true)
    if (result.accepted) {
      expect(result.result.ok).toBe(true)
      expect(result.result.commandId).toBe('cmd_1')
    }
    expect(execute).toHaveBeenCalledWith('RUN_MALWARE_SCAN', { scope: 'quick' })
    expect(seen.has('nonce-1')).toBe(true)
  })

  it('rejects nonce replay', async () => {
    const seen = new Set<string>(['nonce-1'])
    const result = await processVerifiedCommand({
      serverPublicKeyPem: server.publicKeyPem,
      deviceId,
      cmd: makeCmd(),
      seenNonces: seen,
      now: Date.now(),
      execute: defaultCommandExecutor,
    })
    expect(result).toEqual({ accepted: false, reason: 'nonce replay' })
  })

  it('rejects expired commands', async () => {
    const result = await processVerifiedCommand({
      serverPublicKeyPem: server.publicKeyPem,
      deviceId,
      cmd: makeCmd({
        expiresAt: new Date(Date.now() - 1000).toISOString(),
        nonce: 'n-exp',
      }),
      seenNonces: new Set(),
      now: Date.now(),
      execute: defaultCommandExecutor,
    })
    expect(result).toEqual({ accepted: false, reason: 'command expired' })
  })

  it('rejects forged (non-server) signatures', async () => {
    const attacker = generateDeviceKeyPair()
    const forged = makeCmd({ nonce: 'n-forge' })
    // Re-sign with attacker key over same canonical fields
    const { signature: _drop, ...unsigned } = forged
    const bad: CommandEnvelope = {
      ...unsigned,
      signature: signMessage(attacker.privateKeyPem, [
        unsigned.commandId, unsigned.deviceId, unsigned.type,
        JSON.stringify(unsigned.parameters), unsigned.issuedAt, unsigned.expiresAt, unsigned.nonce,
      ].join('\n')),
    }
    const result = await processVerifiedCommand({
      serverPublicKeyPem: server.publicKeyPem,
      deviceId,
      cmd: bad,
      seenNonces: new Set(),
      now: Date.now(),
      execute: defaultCommandExecutor,
    })
    expect(result).toEqual({ accepted: false, reason: 'invalid server signature' })
  })

  it('rejects device id mismatch', async () => {
    const result = await processVerifiedCommand({
      serverPublicKeyPem: server.publicKeyPem,
      deviceId: 'dev_other',
      cmd: makeCmd({ nonce: 'n-mismatch' }),
      seenNonces: new Set(),
      now: Date.now(),
      execute: defaultCommandExecutor,
    })
    expect(result).toEqual({ accepted: false, reason: 'device id mismatch' })
  })
})

describe('defaultCommandExecutor', () => {
  it('returns stub inventory for REQUEST_INVENTORY', async () => {
    const r = await defaultCommandExecutor('REQUEST_INVENTORY', {})
    expect(r.ok).toBe(true)
    expect(r.stub).toBe(true)
    expect(r.type).toBe('REQUEST_INVENTORY')
  })
})

describe('isValidPairingCode', () => {
  it('accepts dashed and undashed 8-char hex codes', async () => {
    const { isValidPairingCode, normalizePairingCode } = await import('./device-command-agent')
    expect(normalizePairingCode('a9338f5c')).toBe('A933-8F5C')
    expect(normalizePairingCode('A933-8F5C')).toBe('A933-8F5C')
    expect(isValidPairingCode('A933-8F5C')).toBe(true)
    expect(isValidPairingCode('a933-8f5c')).toBe(true)
    expect(isValidPairingCode('A9338F5C')).toBe(true)
    expect(isValidPairingCode('AB')).toBe(false)
    expect(isValidPairingCode('RUN_SHELL')).toBe(false)
    expect(isValidPairingCode('K7Q2-9F3M')).toBe(false) // non-hex letters
  })
})
