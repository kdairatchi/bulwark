/**
 * Bounded remote-scan handlers for the device API.
 * Inventory + risk-engine posture + offline LotL/technique grep.
 * Not full YARA / NVD / ClamAV marathons.
 */

import type { InstalledApp } from '../platform/types'
import type { InstalledProgram } from '../../shared/types'
import { analyzeInstalledApps, type InventoryFinding } from './desktop-inventory'
import { buildAppRiskReport } from './risk-engine'
import type { CommandType } from '../../cloud/device-api/commands'
import {
  hitsToCloudFindings,
  scanProcessLolbins,
  scanPersistenceLolbins,
  matchLolbinContent,
  getLolbinCatalogInfo,
} from './lolbin-scanner'
import { matchKevAgainstApps, kevHitsToCloudFindings, getKevCatalogInfo } from './kev-matcher'
import { scanAppsWithOsv } from './osv-client'

export type CloudScanFinding = InventoryFinding

export interface RemoteScanResult {
  ok: boolean
  stub: boolean
  type: CommandType
  findings: number
  threatsFound: number
  postureScore?: number
  appsAssessed: number
  scope: string
  note?: string
  error?: string
  parameters: Record<string, unknown>
  /** Embedded for agent sync; stripped before posting command results. */
  _findings: CloudScanFinding[]
}

export function installedAppsToPrograms(apps: InstalledApp[]): InstalledProgram[] {
  return apps.map((a, i) => ({
    id: `inv_${i}_${(a.name || 'app').slice(0, 48)}`,
    displayName: a.name || 'unknown',
    publisher: a.publisher || '',
    displayVersion: a.version || '',
    installDate: a.installDate || '',
    estimatedSize: a.sizeKb || 0,
    installLocation: '',
    uninstallString: '',
    quietUninstallString: '',
    displayIcon: '',
    registryKey: '',
    isSystemComponent: false,
    isWindowsInstaller: false,
    lastUsed: 0,
  }))
}

function riskToCloudFindings(
  apps: InstalledApp[],
  opts: { minScore?: number; familyOnly?: Array<'needs_attention' | 'dangerous'> } = {},
): CloudScanFinding[] {
  const report = buildAppRiskReport(installedAppsToPrograms(apps))
  const minScore = opts.minScore ?? 40
  const familyOnly = opts.familyOnly
  const out: CloudScanFinding[] = []
  for (const f of report.findings) {
    if (familyOnly && !familyOnly.includes(f.familyStatus as 'needs_attention' | 'dangerous')) {
      continue
    }
    if (!familyOnly && f.score < minScore) continue
    const reason = f.evidence[0] || f.recommendedAction || `risk_${f.level}`
    out.push({
      level: f.status === 'unknown' ? f.level : f.status,
      subjectName: f.subjectName,
      reason: reason.slice(0, 200),
      category: 'risk',
    })
  }
  return out
}

/** Health: inventory heuristics + posture score summary. */
export function runHealthAssessment(
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): RemoteScanResult {
  const inventoryFindings = analyzeInstalledApps(apps)
  const report = buildAppRiskReport(installedAppsToPrograms(apps))
  const findings: CloudScanFinding[] = [
    ...inventoryFindings,
    {
      level: report.postureScore >= 80 ? 'safe' : report.postureScore >= 50 ? 'potential_match' : 'likely_affected',
      subjectName: 'device_posture',
      reason: `posture_score_${report.postureScore}`,
      category: 'health',
    },
  ]
  return {
    ok: true,
    stub: false,
    type: 'RUN_HEALTH_ASSESSMENT',
    findings: findings.length,
    threatsFound: inventoryFindings.filter((f) => f.reason === 'suspicious_app_name').length,
    postureScore: report.postureScore,
    appsAssessed: apps.length,
    scope: 'inventory_posture',
    note: 'Inventory posture + risk-engine score (not full OS health suite)',
    parameters,
    _findings: findings.slice(0, 200),
  }
}

async function collectLolbinFindings(opts?: {
  techniquesOnly?: boolean
  includeVulnHeuristics?: boolean
}): Promise<InventoryFinding[]> {
  const [processHits, persistHits] = await Promise.all([
    scanProcessLolbins(),
    scanPersistenceLolbins(),
  ])
  const merged = [...processHits, ...persistHits]
  const filtered = merged.filter((h) => {
    if (opts?.techniquesOnly) {
      return h.category === 'technique'
        || (opts.includeVulnHeuristics && h.category === 'vuln_heuristic')
    }
    return true
  })
  return hitsToCloudFindings(filtered)
}

/** Quick malware: inventory heuristics + LotL/technique process grep. */
export async function runMalwareScanQuick(
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): Promise<RemoteScanResult> {
  const scope = typeof parameters.scope === 'string' ? parameters.scope : 'quick'
  const nameHits = analyzeInstalledApps(apps).filter((f) => f.reason === 'suspicious_app_name')
  const riskHits = riskToCloudFindings(apps, { familyOnly: ['needs_attention', 'dangerous'] })
  const lolHits = await collectLolbinFindings()
  const catalog = (() => {
    try { return getLolbinCatalogInfo() } catch { return { version: '0', ruleCount: 0 } }
  })()
  const findings = scope === 'lolbins' || scope === 'lotl'
    ? [...lolHits, ...nameHits].slice(0, 200)
    : [...nameHits, ...riskHits, ...lolHits].slice(0, 200)
  return {
    ok: true,
    stub: false,
    type: 'RUN_MALWARE_SCAN',
    findings: findings.length,
    threatsFound: findings.length,
    appsAssessed: apps.length,
    scope,
    note: `Inventory + offline LotL/technique/vuln-heuristic grep on process+persistence (catalog v${catalog.version}, ${catalog.ruleCount} rules) — not full YARA/disk/CVE feed`,
    parameters,
    _findings: findings,
  }
}

/**
 * Vulnerability posture + offline KEV name/version match + technique/vuln-heuristic grep.
 * Optional OSV.dev queries when parameters.osv === true (soft-fail, bounded).
 * Full NVD bulk + EPSS enrichment remains incomplete Phase 5 work.
 */
export async function runVulnerabilityScanPosture(
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): Promise<RemoteScanResult> {
  const posture = riskToCloudFindings(apps, { minScore: 35 })
  const techniqueHits = await collectLolbinFindings({
    techniquesOnly: true,
    includeVulnHeuristics: true,
  })
  // Also grep install paths / names for technique + vuln markers (rare but cheap).
  const nameBlob = apps.map((a) => `${a.name} ${a.publisher}`).join('\n')
  const nameTech = hitsToCloudFindings(
    matchLolbinContent(nameBlob, 'content').filter(
      (h) => h.category === 'technique' || h.category === 'vuln_heuristic',
    ),
  )

  let kevInfo = { version: '0', entryCount: 0 }
  try { kevInfo = getKevCatalogInfo() } catch { /* catalog missing in odd test layouts */ }
  const kevHits = kevHitsToCloudFindings(matchKevAgainstApps(apps))

  const enableOsv = parameters.osv === true || parameters.osv === 'true'
  const osvHits = enableOsv ? await scanAppsWithOsv(apps) : []

  const findings = [...kevHits, ...osvHits, ...posture, ...techniqueHits, ...nameTech].slice(0, 200)
  const cveLike = kevHits.length + osvHits.length
  return {
    ok: true,
    stub: false,
    type: 'RUN_VULNERABILITY_SCAN',
    findings: findings.length,
    threatsFound: findings.length,
    postureScore: buildAppRiskReport(installedAppsToPrograms(apps)).postureScore,
    appsAssessed: apps.length,
    scope: enableOsv
      ? 'kev_osv_posture_technique'
      : 'kev_posture_technique',
    note: `Offline KEV match (catalog v${kevInfo.version}, ${kevInfo.entryCount} entries, ${cveLike} CVE-like hits)`
      + (enableOsv ? ' + bounded OSV queries' : '')
      + ' — full NVD/EPSS Phase 5 still incomplete (not a live zero-day feed)',
    parameters,
    _findings: findings,
  }
}

export async function executeRemoteScan(
  type: 'RUN_HEALTH_ASSESSMENT' | 'RUN_MALWARE_SCAN' | 'RUN_VULNERABILITY_SCAN',
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): Promise<RemoteScanResult> {
  switch (type) {
    case 'RUN_HEALTH_ASSESSMENT':
      return runHealthAssessment(apps, parameters)
    case 'RUN_MALWARE_SCAN':
      return runMalwareScanQuick(apps, parameters)
    case 'RUN_VULNERABILITY_SCAN':
      return runVulnerabilityScanPosture(apps, parameters)
  }
}

/** Map dashboard scan kind → allowlisted command type. */
export function scanKindToCommandType(kind: string): CommandType | null {
  switch (kind.trim().toLowerCase()) {
    case 'health':
    case 'health_assessment':
    case 'run_health_assessment':
      return 'RUN_HEALTH_ASSESSMENT'
    case 'malware':
    case 'malware_scan':
    case 'run_malware_scan':
    case 'lolbins':
    case 'lotl':
      return 'RUN_MALWARE_SCAN'
    case 'vulnerability':
    case 'vuln':
    case 'vulnerability_scan':
    case 'run_vulnerability_scan':
      return 'RUN_VULNERABILITY_SCAN'
    default:
      return null
  }
}
