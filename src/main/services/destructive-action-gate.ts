/**
 * Shared gate for destructive desktop actions (clean, quarantine, …).
 *
 * Product rule (Phase 1): when requireRestorePoint is enabled on Windows,
 * refuse to proceed if a System Restore point cannot be created. Dry-run
 * always passes. Non-Windows platforms report platform_unsupported and allow
 * the action (no System Restore equivalent).
 */

import type { RestorePointResult } from './restore-point'

export type DestructiveSkipReason =
  | 'dry_run'
  | 'disabled'
  | 'platform_unsupported'
  | 'force'
  | 'restore_failed'
  | 'restore_throttled'

export interface DestructiveGateResult {
  allowed: boolean
  restoreAttempted: boolean
  restoreSucceeded: boolean
  skipReason?: DestructiveSkipReason
  error?: string
}

export interface DestructiveGateDeps {
  platform?: NodeJS.Platform
  createRestorePoint: (description: string) => Promise<RestorePointResult>
}

const defaultDeps = (): DestructiveGateDeps => ({
  platform: process.platform,
  createRestorePoint: async (description) => {
    const { createRestorePoint } = await import('./restore-point')
    return createRestorePoint(description)
  },
})

/** Windows treats the 24h Checkpoint-Computer throttle as a recent valid checkpoint. */
export function isRestoreFrequencyThrottle(error?: string): boolean {
  if (!error) return false
  const msg = error.toLowerCase()
  return msg.includes('frequency') || msg.includes('1440') || msg.includes('already created')
}

/**
 * Decide whether a destructive action may proceed.
 */
export async function assertDestructiveAllowed(opts: {
  description: string
  dryRun?: boolean
  requireRestorePoint?: boolean
  /** Bypass the restore requirement (CLI --force). */
  force?: boolean
  deps?: DestructiveGateDeps
}): Promise<DestructiveGateResult> {
  const deps = opts.deps ?? defaultDeps()
  const platform = deps.platform ?? process.platform

  if (opts.dryRun) {
    return {
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'dry_run',
    }
  }

  if (opts.force) {
    return {
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'force',
    }
  }

  if (!opts.requireRestorePoint) {
    return {
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'disabled',
    }
  }

  if (platform !== 'win32') {
    return {
      allowed: true,
      restoreAttempted: false,
      restoreSucceeded: false,
      skipReason: 'platform_unsupported',
    }
  }

  const result = await deps.createRestorePoint(opts.description)
  if (result.success) {
    return {
      allowed: true,
      restoreAttempted: true,
      restoreSucceeded: true,
    }
  }

  if (isRestoreFrequencyThrottle(result.error)) {
    return {
      allowed: true,
      restoreAttempted: true,
      restoreSucceeded: false,
      skipReason: 'restore_throttled',
      error: result.error,
    }
  }

  return {
    allowed: false,
    restoreAttempted: true,
    restoreSucceeded: false,
    skipReason: 'restore_failed',
    error: result.error || 'Failed to create a System Restore point.',
  }
}
