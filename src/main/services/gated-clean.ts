/**
 * Main-process clean entry point that enforces Phase 1 safety:
 * restore-point gate + optional dry-run.
 *
 * IPC / scheduled / cloud cleans must go through here so the renderer-only
 * CleanerPage hard-stop cannot be bypassed.
 */

import type { CleanOptions, CleanResult, DeletionOrigin } from '../../shared/types'
import { cleanItems } from './file-utils'
import { assertDestructiveAllowed, type DestructiveGateResult } from './destructive-action-gate'
import { getSettings } from './settings-store'

export function blockedCleanResult(gate: DestructiveGateResult): CleanResult {
  return {
    totalCleaned: 0,
    filesDeleted: 0,
    filesSkipped: 0,
    errors: [{
      path: '',
      reason: gate.error || 'restore_point_required',
    }],
    needsElevation: false,
    blockedByRestoreGate: true,
  }
}

/** Run the restore gate using current cleaner settings. */
export async function assertCleanAllowed(opts: {
  dryRun?: boolean
  force?: boolean
  description?: string
} = {}): Promise<DestructiveGateResult> {
  const requireRestorePoint = getSettings().cleaner.requireRestorePoint === true
  return assertDestructiveAllowed({
    description: opts.description || `Bulwark clean — ${new Date().toISOString()}`,
    dryRun: opts.dryRun === true,
    requireRestorePoint,
    force: opts.force === true,
  })
}

/**
 * Gate + cleanItems. Prefer this over calling cleanItems directly from IPC/cloud.
 */
export async function gatedCleanItems(
  itemIds: unknown,
  onProgress?: (processed: number, total: number, currentPath: string, cleanedSize: number) => void,
  origin: DeletionOrigin = 'local',
  options: CleanOptions = {},
): Promise<CleanResult> {
  const dryRun = options.dryRun === true
  const gate = await assertCleanAllowed({ dryRun, force: options.force === true })
  if (!gate.allowed) return blockedCleanResult(gate)
  return cleanItems(itemIds, onProgress, origin, { dryRun })
}
