/**
 * Unified structured finding model — shared across desktop scanners, cloud wire
 * format, and Activity explainability. Scanners keep their native result types
 * and project into UnifiedFinding via adapters (see finding-adapters.ts).
 *
 * Design rules:
 * - `level` is always a RiskLevel (severity). Never overload it with lifecycle status.
 * - `status` is FindingStatus (lifecycle / match confidence).
 * - Cloud wire (`WireFinding`) still accepts legacy status-as-level for older agents.
 */

import type {
  Confidence,
  FamilyStatus,
  FindingStatus,
  RiskLevel,
} from './risk'

export type FindingType =
  | 'application_risk'
  | 'malware'
  | 'vulnerability'
  | 'network'
  | 'privacy'
  | 'technique'
  | 'inventory'
  | 'health'

/** Canonical structured finding used across scanners. */
export interface UnifiedFinding {
  id: string
  type: FindingType
  subjectId?: string
  subjectName: string
  level: RiskLevel
  status: FindingStatus
  /** Taxonomy: kev | osv | lolbin | malware | risk | privacy | network | … */
  category: string
  /** Machine-readable reason code or short evidence line. */
  reason: string
  evidence?: string[]
  recommendedAction?: string
  fixRecommendation?: string
  confidence?: Confidence
  familyStatus?: FamilyStatus
  score?: number
  createdAt: string
}

/**
 * Device-API / inventory wire shape. Prefer RiskLevel in `level` + FindingStatus
 * in `status`. Legacy agents may still put FindingStatus into `level`.
 */
export interface WireFinding {
  level: string
  subjectName: string
  reason: string
  status?: FindingStatus
  category?: string
  fixRecommendation?: string
}

const RISK_LEVELS: readonly RiskLevel[] = ['safe', 'low', 'medium', 'high', 'critical']

const FINDING_STATUSES: readonly FindingStatus[] = [
  'confirmed_affected',
  'likely_affected',
  'potential_match',
  'not_exploitable',
  'fixed',
  'accepted_risk',
  'false_positive',
  'unknown',
]

export function isRiskLevel(value: string): value is RiskLevel {
  return (RISK_LEVELS as readonly string[]).includes(value)
}

export function isFindingStatusValue(value: string): value is FindingStatus {
  return (FINDING_STATUSES as readonly string[]).includes(value)
}

/** Map coarse severity strings onto RiskLevel. */
export function coerceRiskLevel(raw: string | undefined | null): RiskLevel {
  const s = (raw || '').toLowerCase().trim()
  if (isRiskLevel(s)) return s
  if (s.includes('critical') || s === 'dangerous') return 'critical'
  if (s.includes('high') || s.includes('confirmed') || s.includes('likely')) return 'high'
  if (s.includes('medium') || s.includes('potential') || s.includes('attention')) return 'medium'
  if (s.includes('low')) return 'low'
  if (s === 'safe' || s === 'info' || s === 'allow') return 'safe'
  return 'medium'
}

/** Prefer explicit status; else treat status-as-level legacy; else potential_match. */
export function coerceFindingStatus(
  status: string | undefined | null,
  levelFallback?: string | null,
): FindingStatus {
  if (status && isFindingStatusValue(status)) return status
  if (levelFallback && isFindingStatusValue(levelFallback)) return levelFallback
  return 'potential_match'
}

/** Project a unified finding onto the device-API wire shape (level/status split). */
export function toWireFinding(f: UnifiedFinding): WireFinding {
  return {
    level: f.level,
    subjectName: f.subjectName,
    reason: f.reason.slice(0, 200),
    status: f.status,
    category: f.category,
    ...(f.fixRecommendation
      ? { fixRecommendation: f.fixRecommendation.slice(0, 240) }
      : f.recommendedAction
        ? { fixRecommendation: f.recommendedAction.slice(0, 240) }
        : {}),
  }
}

/** Plain-language explainability for a finding (why / confidence / next step). */
export function explainFinding(f: UnifiedFinding): {
  why: string
  confidence: string
  nextStep: string
} {
  const why = f.evidence?.[0]
    || f.reason
    || `${f.type} finding on ${f.subjectName}`
  const confidence = f.confidence
    ? f.confidence === 'strong' ? 'Strong evidence'
      : f.confidence === 'moderate' ? 'Moderate evidence'
        : 'Limited evidence'
    : f.status === 'confirmed_affected' ? 'Confirmed match'
      : f.status === 'likely_affected' ? 'Likely match'
        : f.status === 'potential_match' ? 'Possible match'
          : 'Status unknown'
  const nextStep = f.fixRecommendation
    || f.recommendedAction
    || defaultNextStep(f.type)
  return { why, confidence, nextStep }
}

function defaultNextStep(type: FindingType): string {
  switch (type) {
    case 'malware':
      return 'Review the detection, quarantine if confirmed, or allowlist if it is a false positive.'
    case 'vulnerability':
      return 'Open Findings, review the fix recommendation, and update the package.'
    case 'network':
      return 'Confirm whether the destination is expected; keep blocking if it is not.'
    case 'privacy':
      return 'Enable the privacy protection for this setting, or leave it if you need the feature.'
    case 'technique':
      return 'Inspect the process or persistence entry and remove it if unexpected.'
    case 'application_risk':
      return 'Review the application evidence and uninstall or restrict it if untrusted.'
    case 'health':
      return 'Run a fuller health or malware scan if the posture score stays low.'
    default:
      return 'Review the finding details and decide whether to update, remove, or accept the risk.'
  }
}
