/**
 * Bounded remote-scan handlers for the device API.
 * Inventory + risk-engine posture only — not full YARA / NVD / ClamAV marathons.
 */

import type { InstalledApp } from '../platform/types'
import type { InstalledProgram } from '../../shared/types'
import { analyzeInstalledApps, type InventoryFinding } from './desktop-inventory'
import { buildAppRiskReport } from './risk-engine'
import type { CommandType } from '../../cloud/device-api/commands'

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

/** Quick malware: suspicious names + elevated risk-engine family statuses. */
export function runMalwareScanQuick(
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): RemoteScanResult {
  const nameHits = analyzeInstalledApps(apps).filter((f) => f.reason === 'suspicious_app_name')
  const riskHits = riskToCloudFindings(apps, { familyOnly: ['needs_attention', 'dangerous'] })
  const findings = [...nameHits, ...riskHits].slice(0, 200)
  return {
    ok: true,
    stub: false,
    type: 'RUN_MALWARE_SCAN',
    findings: findings.length,
    threatsFound: findings.length,
    appsAssessed: apps.length,
    scope: typeof parameters.scope === 'string' ? parameters.scope : 'quick',
    note: 'Quick inventory heuristics — not full YARA/ClamAV disk scan',
    parameters,
    _findings: findings,
  }
}

/** Vulnerability posture: elevated risk findings (no live NVD/OSV yet). */
export function runVulnerabilityScanPosture(
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): RemoteScanResult {
  const findings = riskToCloudFindings(apps, { minScore: 35 }).slice(0, 200)
  return {
    ok: true,
    stub: false,
    type: 'RUN_VULNERABILITY_SCAN',
    findings: findings.length,
    threatsFound: findings.length,
    postureScore: buildAppRiskReport(installedAppsToPrograms(apps)).postureScore,
    appsAssessed: apps.length,
    scope: 'inventory_posture',
    note: 'Posture risk only — CVE/OSV matching is Phase 5',
    parameters,
    _findings: findings,
  }
}

export function executeRemoteScan(
  type: 'RUN_HEALTH_ASSESSMENT' | 'RUN_MALWARE_SCAN' | 'RUN_VULNERABILITY_SCAN',
  apps: InstalledApp[],
  parameters: Record<string, unknown> = {},
): RemoteScanResult {
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
