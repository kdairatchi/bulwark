/**
 * Thin adapters: scanner-native types → UnifiedFinding / WireFinding.
 * Prefer these over inventing parallel finding shapes in each scanner.
 */

import type { MalwareThreat, PrivacySetting, CveVulnerability } from './types'
import type { NetworkEvent } from './network-guard'
import type { Finding, FindingStatus, RiskLevel } from './risk'
import {
  coerceFindingStatus,
  coerceRiskLevel,
  explainFinding,
  toWireFinding,
  type FindingType,
  type UnifiedFinding,
  type WireFinding,
} from './finding'

let seq = 0
function nextId(prefix: string): string {
  seq += 1
  return `${prefix}_${Date.now().toString(36)}_${seq}`
}

function severityToLevel(severity: string): RiskLevel {
  return coerceRiskLevel(severity)
}

function severityToStatus(severity: string): FindingStatus {
  const s = severity.toLowerCase()
  if (s === 'critical' || s === 'high') return 'likely_affected'
  if (s === 'medium' || s === 'low') return 'potential_match'
  return 'potential_match'
}

/** App-risk Finding (risk.ts) → unified. */
export function fromRiskFinding(f: Finding): UnifiedFinding {
  return {
    id: f.id,
    type: 'application_risk',
    subjectId: f.subjectId,
    subjectName: f.subjectName,
    level: f.level,
    status: f.status,
    category: 'risk',
    reason: f.evidence[0] || f.recommendedAction || `risk_${f.level}`,
    evidence: f.evidence,
    recommendedAction: f.recommendedAction,
    fixRecommendation: f.recommendedAction,
    confidence: f.confidence,
    familyStatus: f.familyStatus,
    score: f.score,
    createdAt: f.createdAt,
  }
}

/** Legacy / cloud inventory wire row → unified (handles status-as-level). */
export function fromWireFinding(
  f: WireFinding,
  opts: { type?: FindingType; id?: string; createdAt?: string } = {},
): UnifiedFinding {
  const status = coerceFindingStatus(f.status, f.level)
  const level = coerceRiskLevel(f.level)
  return {
    id: opts.id || nextId('wire'),
    type: opts.type || categoryToType(f.category),
    subjectName: f.subjectName,
    level,
    status,
    category: f.category || 'inventory',
    reason: f.reason,
    fixRecommendation: f.fixRecommendation,
    createdAt: opts.createdAt || new Date().toISOString(),
  }
}

function categoryToType(category?: string): FindingType {
  const c = (category || '').toLowerCase()
  if (c === 'kev' || c === 'osv' || c === 'cve') return 'vulnerability'
  if (c === 'malware' || c === 'lolbin') return 'malware'
  if (c === 'technique' || c === 'vuln_heuristic') return 'technique'
  if (c === 'privacy') return 'privacy'
  if (c === 'network') return 'network'
  if (c === 'risk') return 'application_risk'
  if (c === 'health') return 'health'
  return 'inventory'
}

/** Local malware UI threat → unified. */
export function fromMalwareThreat(t: MalwareThreat, createdAt = new Date().toISOString()): UnifiedFinding {
  return {
    id: t.id || nextId('malware'),
    type: 'malware',
    subjectId: t.path,
    subjectName: t.detectionName || t.fileName,
    level: severityToLevel(t.severity),
    status: severityToStatus(t.severity),
    category: 'malware',
    reason: t.source === 'defender' ? 'defender_detection' : t.source === 'signature' ? 'signature_match' : 'heuristic_match',
    evidence: [
      `path=${t.path}`,
      `file=${t.fileName}`,
      `source=${t.source}`,
      ...(t.details ? [t.details.slice(0, 200)] : []),
    ],
    recommendedAction: 'Quarantine or delete the file if the detection is confirmed.',
    createdAt,
  }
}

/**
 * Network Guard event → unified finding (block/alert only).
 * Allow events are not findings — keep them on the network-events stream.
 */
export function fromNetworkEvent(
  e: NetworkEvent,
  opts: { id?: string } = {},
): UnifiedFinding | null {
  if (e.decision === 'allow') return null
  const level: RiskLevel = e.decision === 'block'
    ? (e.confidence >= 0.8 ? 'critical' : 'high')
    : (e.confidence >= 0.7 ? 'high' : 'medium')
  return {
    id: opts.id || nextId('net'),
    type: 'network',
    subjectName: e.destination,
    level,
    status: e.confidence >= 0.85 ? 'likely_affected' : 'potential_match',
    category: e.category || 'network',
    reason: e.reason,
    evidence: [
      `decision=${e.decision}`,
      `confidence=${Math.round(e.confidence * 100)}%`,
      ...(e.matchedIndicator ? [`indicator=${e.matchedIndicator}`] : []),
      ...(e.port != null ? [`port=${e.port}`] : []),
    ],
    recommendedAction: e.decision === 'block'
      ? 'Keep this destination blocked unless you intentionally need it.'
      : 'Review the destination and block it if it is unexpected.',
    confidence: e.confidence >= 0.85 ? 'strong' : e.confidence >= 0.5 ? 'moderate' : 'weak',
    createdAt: e.timestamp,
  }
}

/** Privacy setting that is NOT yet protected → finding. */
export function fromPrivacySetting(
  s: PrivacySetting,
  createdAt = new Date().toISOString(),
): UnifiedFinding | null {
  if (s.enabled) return null
  return {
    id: `privacy_${s.id}`,
    type: 'privacy',
    subjectId: s.id,
    subjectName: s.label,
    level: s.requiresAdmin ? 'medium' : 'low',
    status: 'potential_match',
    category: 'privacy',
    reason: `privacy_unprotected:${s.category}`,
    evidence: [s.description, `category=${s.category}`, `reversible=${s.reversible}`],
    recommendedAction: `Enable “${s.label}” in Privacy Shield to harden this setting.`,
    createdAt,
  }
}

/** CVE library row → unified vulnerability finding. */
export function fromCveVulnerability(
  v: CveVulnerability,
): UnifiedFinding {
  return {
    id: `cve_${v.cveId}_${v.id}`,
    type: 'vulnerability',
    subjectId: String(v.id),
    subjectName: v.cveId,
    level: severityToLevel(v.severity),
    status: 'likely_affected',
    category: 'cve',
    reason: `${v.appName}@${v.installedVersion}`,
    evidence: [
      ...(v.description ? [v.description.slice(0, 200)] : []),
      ...(v.cvssScore != null ? [`cvss=${v.cvssScore}`] : []),
      ...(v.fixedIn ? [`fixedIn=${v.fixedIn}`] : []),
    ],
    fixRecommendation: v.fixedIn
      ? `Update ${v.appName} to ${v.fixedIn} or newer.`
      : `Update ${v.appName} to a patched version.`,
    createdAt: v.firstDetectedAt,
  }
}

export { toWireFinding, explainFinding }

/** Convenience: risk Finding → cloud wire with level/status split. */
export function riskFindingToWire(f: Finding): WireFinding {
  return toWireFinding(fromRiskFinding(f))
}

/** Convenience: malware threat → cloud wire. */
export function malwareThreatToWire(t: MalwareThreat): WireFinding {
  return toWireFinding(fromMalwareThreat(t))
}
