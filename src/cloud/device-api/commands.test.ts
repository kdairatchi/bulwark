import { describe, it, expect } from 'vitest'
import { generateDeviceKeyPair } from './crypto'
import { signCommand, verifyCommandEnvelope, isAllowedCommand, ALLOWED_COMMANDS, type CommandEnvelope } from './commands'

const now = 1_700_000_000_000
function makeCmd(server: { privateKeyPem: string }, overrides: Partial<Omit<CommandEnvelope, 'signature'>> = {}): CommandEnvelope {
  return signCommand(server.privateKeyPem, {
    commandId: 'cmd_1',
    deviceId: 'dev_1',
    type: 'RUN_MALWARE_SCAN',
    parameters: {},
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
    nonce: 'nonce-1',
    ...overrides,
  })
}

describe('commands · allowlist', () => {
  it('only recognizes allowlisted command types (no arbitrary exec)', () => {
    for (const t of ALLOWED_COMMANDS) expect(isAllowedCommand(t)).toBe(true)
    expect(isAllowedCommand('RUN_SHELL')).toBe(false)
    expect(isAllowedCommand('EXEC')).toBe(false)
  })
})

describe('commands · sign + verify', () => {
  const server = generateDeviceKeyPair()

  it('accepts a valid, in-date, allowlisted command with a good signature', () => {
    const cmd = makeCmd(server)
    expect(verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_1', seenNonces: new Set() })).toEqual({ ok: true })
  })

  it('rejects a command signed by a different (forged) key', () => {
    const attacker = generateDeviceKeyPair()
    const cmd = makeCmd(attacker)
    const r = verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_1', seenNonces: new Set() })
    expect(r).toMatchObject({ ok: false, reason: 'invalid server signature' })
  })

  it('rejects a tampered command (type changed after signing)', () => {
    const cmd = makeCmd(server)
    const tampered = { ...cmd, type: 'QUARANTINE_FILE' as const }
    expect(verifyCommandEnvelope(server.publicKeyPem, tampered, { now, deviceId: 'dev_1', seenNonces: new Set() }).ok).toBe(false)
  })

  it('rejects an expired command', () => {
    const cmd = makeCmd(server, { expiresAt: new Date(now - 1000).toISOString() })
    expect(verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_1', seenNonces: new Set() })).toMatchObject({ ok: false, reason: 'command expired' })
  })

  it('rejects a replayed nonce', () => {
    const cmd = makeCmd(server)
    expect(verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_1', seenNonces: new Set(['nonce-1']) })).toMatchObject({ ok: false, reason: 'nonce replay' })
  })

  it('rejects a command addressed to a different device', () => {
    const cmd = makeCmd(server)
    expect(verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_OTHER', seenNonces: new Set() })).toMatchObject({ ok: false, reason: 'device id mismatch' })
  })

  it('rejects a non-allowlisted type even if signed', () => {
    // Force a bad type past TS to simulate a malicious/broken server.
    const cmd = signCommand(server.privateKeyPem, {
      commandId: 'c', deviceId: 'dev_1', type: 'RUN_SHELL' as never, parameters: {},
      issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1000).toISOString(), nonce: 'n',
    })
    expect(verifyCommandEnvelope(server.publicKeyPem, cmd, { now, deviceId: 'dev_1', seenNonces: new Set() })).toMatchObject({ ok: false, reason: 'command type not allowlisted' })
  })
})
