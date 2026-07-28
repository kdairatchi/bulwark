import { dialog, ipcMain, shell } from 'electron'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { isAbsolute, relative, resolve } from 'path'
import { IPC } from '../../shared/channels'
import type {
  UtilityPowerPlanSetResult,
  UtilityPowerPlanState,
  UtilityPowerPlanTarget,
  UtilityShutUpLaunchResult,
  UtilityTweakActionResult,
  UtilityTweakMetadata,
  UtilityTweakPresetExportPayload,
  UtilityTweakPresetImportOutcome,
  UtilityTweaksScanResult,
} from '../../shared/types'
import {
  applyTweaks,
  buildUtilityTweakPreset,
  getCatalog,
  getUtilityPowerPlan,
  parseUtilityTweakPreset,
  revertTweaks,
  scanTweaks,
  setUtilityPowerPlan,
  UTILITY_POWER_PLAN_TARGETS,
  validateUtilityTweakIds,
} from '../services/utility-tweaks'
import type { WindowGetter } from './index'

function validatePowerPlanTarget(input: unknown): UtilityPowerPlanTarget | null {
  if (typeof input !== 'string') return null
  return UTILITY_POWER_PLAN_TARGETS.includes(input as UtilityPowerPlanTarget)
    ? input as UtilityPowerPlanTarget
    : null
}

function parseExportPayload(input: unknown): UtilityTweakPresetExportPayload | null {
  if (!input || typeof input !== 'object') return null
  const obj = input as Record<string, unknown>
  const selected = validateUtilityTweakIds(obj.selected)
  if (!selected || selected.length === 0) return null

  let applied: Record<string, boolean> | undefined
  if (obj.applied && typeof obj.applied === 'object' && !Array.isArray(obj.applied)) {
    applied = {}
    for (const [id, value] of Object.entries(obj.applied as Record<string, unknown>)) {
      if (typeof value === 'boolean') applied[id] = value
    }
  }

  return { selected, applied }
}

const SHUTUP10_DOWNLOAD_URL = 'https://www.oo-software.com/en/shutup10'

function pathContainsParentSegment(value: string): boolean {
  return value.split(/[\\/]+/).includes('..')
}

function isPathUnderRoot(candidate: string, root: string): boolean {
  const rel = relative(root, candidate)
  return rel === '' || (rel.length > 0 && !rel.startsWith('..') && !isAbsolute(rel))
}

export function getResolvedShutUp10Roots(env: NodeJS.ProcessEnv = process.env): string[] {
  const roots = [
    env.ProgramFiles,
    env['ProgramFiles(x86)'],
    env.LOCALAPPDATA,
  ].filter((value): value is string =>
    typeof value === 'string'
    && value.length > 0
    && isAbsolute(value)
    && !pathContainsParentSegment(value)
  )

  return [...new Set(roots.map((root) => resolve(root)))]
}

export function isShutUp10CandidatePathAllowed(candidate: string, roots = getResolvedShutUp10Roots()): boolean {
  if (pathContainsParentSegment(candidate)) return false
  const resolvedCandidate = resolve(candidate)
  return roots.some((root) => isPathUnderRoot(resolvedCandidate, root))
}

export function getShutUp10Candidates(env: NodeJS.ProcessEnv = process.env): string[] {
  const roots = getResolvedShutUp10Roots(env)

  const relativePaths = [
    ['O&O ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'ShutUp10++', 'OOSU10.exe'],
    ['OO Software', 'O&O ShutUp10++', 'OOSU10.exe'],
    ['OOSU10', 'OOSU10.exe'],
  ]

  return roots.flatMap((root) =>
    relativePaths
      .map((parts) => resolve(root, ...parts))
      .filter((candidate) => isShutUp10CandidatePathAllowed(candidate, roots))
  )
}

async function launchShutUp10(): Promise<UtilityShutUpLaunchResult> {
  if (process.platform === 'win32') {
    const roots = getResolvedShutUp10Roots()
    for (const candidate of getShutUp10Candidates()) {
      const resolvedCandidate = resolve(candidate)
      if (!isShutUp10CandidatePathAllowed(resolvedCandidate, roots)) continue
      if (!existsSync(resolvedCandidate)) continue
      const error = await shell.openPath(resolvedCandidate)
      if (!error) return { opened: true, fallback: false, path: resolvedCandidate }
    }
  }

  await shell.openExternal(SHUTUP10_DOWNLOAD_URL)
  return { opened: true, fallback: true, path: SHUTUP10_DOWNLOAD_URL }
}

export function registerUtilityTweaksIpc(getWindow: WindowGetter): void {
  ipcMain.handle(IPC.UTILITY_TWEAKS_CATALOG, async (): Promise<UtilityTweakMetadata[]> => {
    if (process.platform !== 'win32') return []
    return getCatalog()
  })

  ipcMain.handle(IPC.UTILITY_TWEAKS_SCAN, async (): Promise<UtilityTweaksScanResult> => {
    return scanTweaks()
  })

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_APPLY,
    async (_event, ids: unknown): Promise<UtilityTweakActionResult> => {
      const validIds = validateUtilityTweakIds(ids)
      if (!validIds) {
        return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
      }
      return applyTweaks(validIds)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_REVERT,
    async (_event, ids: unknown): Promise<UtilityTweakActionResult> => {
      const validIds = validateUtilityTweakIds(ids)
      if (!validIds) {
        return { succeeded: 0, failed: 1, errors: [{ id: '*', reason: 'Invalid tweak ID' }] }
      }
      return revertTweaks(validIds)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_POWER_PLAN_GET,
    async (): Promise<UtilityPowerPlanState> => getUtilityPowerPlan(),
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_POWER_PLAN_SET,
    async (_event, target: unknown): Promise<UtilityPowerPlanSetResult> => {
      const validTarget = validatePowerPlanTarget(target)
      if (!validTarget) return { success: false, error: 'Invalid power plan target' }
      return setUtilityPowerPlan(validTarget)
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_SHUTUP10_LAUNCH,
    async (): Promise<UtilityShutUpLaunchResult> => launchShutUp10(),
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_EXPORT_PRESET,
    async (_event, payload: unknown): Promise<string | null> => {
      const parsed = parseExportPayload(payload)
      if (!parsed) return null

      const win = getWindow()
      const opts: Electron.SaveDialogOptions = {
        title: 'Export tweak selection',
        defaultPath: 'bulwrk-tweaks.json',
        filters: [{ name: 'JSON', extensions: ['json'] }],
      }
      const result = process.platform === 'darwin' || !win
        ? await dialog.showSaveDialog(opts)
        : await dialog.showSaveDialog(win, opts)
      if (result.canceled || !result.filePath) return null

      try {
        const file = buildUtilityTweakPreset(parsed.selected, parsed.applied)
        writeFileSync(result.filePath, `${JSON.stringify(file, null, 2)}\n`, 'utf-8')
        return result.filePath
      } catch {
        return null
      }
    },
  )

  ipcMain.handle(
    IPC.UTILITY_TWEAKS_IMPORT_PRESET,
    async (): Promise<UtilityTweakPresetImportOutcome> => {
      const win = getWindow()
      const opts: Electron.OpenDialogOptions = {
        title: 'Import tweak selection',
        properties: ['openFile'],
        filters: [{ name: 'JSON', extensions: ['json'] }],
      }
      const result = process.platform === 'darwin' || !win
        ? await dialog.showOpenDialog(opts)
        : await dialog.showOpenDialog(win, opts)
      if (result.canceled || result.filePaths.length === 0) {
        return { ok: false, reason: 'canceled' }
      }

      const filePath = result.filePaths[0]
      try {
        const rawText = readFileSync(filePath, 'utf-8')
        const parsedJson = JSON.parse(rawText) as unknown
        const parsed = parseUtilityTweakPreset(parsedJson)
        if (!parsed || parsed.selected.length === 0) {
          return { ok: false, reason: 'invalid' }
        }
        return {
          ok: true,
          selected: parsed.selected,
          skipped: parsed.skipped,
          path: filePath,
        }
      } catch {
        return { ok: false, reason: 'invalid' }
      }
    },
  )
}
