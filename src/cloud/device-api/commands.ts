// Secure remote-command model (see docs/threat-model/README.md#remote-command-model).
//
// Commands are server-SIGNED, ALLOWLISTED, EXPIRING, and NONCE-protected. The
// device verifies the server signature, that the type is allowlisted, that the
// command hasn't expired, and that the nonce hasn't been seen — before acting.
// This deliberately excludes arbitrary shell / remote-exec command types.

import { signMessage, verifyMessage } from './crypto'

/** The ONLY command types a device will accept. No arbitrary execution. */
export const ALLOWED_COMMANDS = [
  'REQUEST_INVENTORY',
  'RUN_MALWARE_SCAN',
  'RUN_VULNERABILITY_SCAN',
  'RUN_HEALTH_ASSESSMENT',
  'UPDATE_THREAT_FEEDS',
  'QUARANTINE_FILE',
  'BLOCK_DOMAIN',
  'RESTART_AGENT',
] as const

export type CommandType = (typeof ALLOWED_COMMANDS)[number]

export function isAllowedCommand(type: string): type is CommandType {
  return (ALLOWED_COMMANDS as readonly string[]).includes(type)
}

export interface CommandEnvelope {
  commandId: string
  deviceId: string
  type: CommandType
  parameters: Record<string, unknown>
  issuedAt: string
  expiresAt: string
  nonce: string
  /** Base64 Ed25519 signature by the SERVER key over the canonical string. */
  signature: string
}

/** Deterministic string the server signs / the device verifies. */
export function canonicalCommand(c: Omit<CommandEnvelope, 'signature'>): string {
  return [
    c.commandId,
    c.deviceId,
    c.type,
    JSON.stringify(c.parameters ?? {}),
    c.issuedAt,
    c.expiresAt,
    c.nonce,
  ].join('\n')
}

/** Server-side: build and sign a command envelope. */
export function signCommand(serverPrivateKeyPem: string, unsigned: Omit<CommandEnvelope, 'signature'>): CommandEnvelope {
  return { ...unsigned, signature: signMessage(serverPrivateKeyPem, canonicalCommand(unsigned)) }
}

export type CommandVerifyResult = { ok: true } | { ok: false; reason: string }

/**
 * Device-side verification. Pure over its inputs so it is unit-testable and can
 * be reused verbatim by the desktop/Android agents.
 */
export function verifyCommandEnvelope(
  serverPublicKeyPem: string,
  cmd: CommandEnvelope,
  opts: { now: number; deviceId: string; seenNonces: Set<string> },
): CommandVerifyResult {
  if (!isAllowedCommand(cmd.type)) return { ok: false, reason: 'command type not allowlisted' }
  if (cmd.deviceId !== opts.deviceId) return { ok: false, reason: 'device id mismatch' }
  const exp = Date.parse(cmd.expiresAt)
  if (Number.isNaN(exp) || opts.now > exp) return { ok: false, reason: 'command expired' }
  if (opts.seenNonces.has(cmd.nonce)) return { ok: false, reason: 'nonce replay' }
  const { signature, ...unsigned } = cmd
  if (!verifyMessage(serverPublicKeyPem, canonicalCommand(unsigned), signature)) {
    return { ok: false, reason: 'invalid server signature' }
  }
  return { ok: true }
}
