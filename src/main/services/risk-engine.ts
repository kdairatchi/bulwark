// Deterministic application risk engine.
//
// Given a set of known signals about a subject (an installed program, a startup
// item, later an Android app or a network peer), produce a transparent risk
// assessment: a score, a level, a confidence, the evidence that drove it, and a
// concrete recommended action. There is no machine learning and no LLM in this
// path — the same input always yields the same output. See docs/threat-model.

import type { InstalledProgram } from '../../shared/types'
import type {
  AppRiskReport,
  Confidence,
  FamilyStatus,
  Finding,
  RiskAssessment,
  RiskInput,
  RiskLevel,
  RiskSignal,
  RiskSignalId,
} from '../../shared/risk'

/** Signed weights + evidence templates. Single source of truth for scoring. */
export const RISK_SIGNALS: Record<
  RiskSignalId,
  { key: keyof RiskInput; weight: number; evidence: string }
> = {
  malicious_network_indicator: {
    key: 'maliciousNetworkIndicator',
    weight: 25,
    evidence: 'Connected to an endpoint associated with known-malicious infrastructure',
  },
  unsigned_executable: {
    key: 'unsignedExecutable',
    weight: 25,
    evidence: 'Publisher signature could not be verified (unsigned executable)',
  },
  requests_admin: {
    key: 'requestsAdmin',
    weight: 20,
    evidence: 'Requests administrator privileges',
  },
  unknown_publisher: {
    key: 'unknownPublisher',
    weight: 20,
    evidence: 'Published by an unknown or low-reputation publisher',
  },
  persistence_mechanism: {
    key: 'persistenceMechanism',
    weight: 20,
    evidence: 'Installs a persistence mechanism to survive reboots',
  },
  runs_at_startup: {
    key: 'runsAtStartup',
    weight: 15,
    evidence: 'Starts automatically every time the computer boots',
  },
  unknown_install_source: {
    key: 'unknownInstallSource',
    weight: 15,
    evidence: 'Installed from an unknown source (outside a recognized package manager)',
  },
  recently_created_binary: {
    key: 'recentlyCreatedBinary',
    weight: 10,
    evidence: 'Binary was created very recently',
  },
  temp_directory_binary: {
    key: 'tempDirectoryBinary',
    weight: 10,
    evidence: 'Executable is stored in a temporary directory',
  },
  signed_by_trusted_publisher: {
    key: 'signedByTrustedPublisher',
    weight: -20,
    evidence: 'Signed by a trusted publisher',
  },
  trusted_package_manager: {
    key: 'trustedPackageManager',
    weight: -15,
    evidence: 'Installed through a trusted package manager',
  },
  high_prevalence: {
    key: 'highPrevalence',
    weight: -10,
    evidence: 'Common among legitimate users (high prevalence)',
  },
}

const LEVEL_LABEL: Record<RiskLevel, string> = {
  safe: 'Safe',
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
  critical: 'Critical risk',
}

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  weak: 'Weak',
  moderate: 'Moderate',
  strong: 'Strong',
}

export function levelLabel(level: RiskLevel): string {
  return LEVEL_LABEL[level]
}

export function confidenceLabel(confidence: Confidence): string {
  return CONFIDENCE_LABEL[confidence]
}

function scoreToLevel(score: number): RiskLevel {
  if (score <= 0) return 'safe'
  if (score < 25) return 'low'
  if (score < 50) return 'medium'
  if (score < 75) return 'high'
  return 'critical'
}

/**
 * Confidence reflects how much we actually know — not how bad it is.
 * A decisive malicious-network match is always strong. Otherwise more
 * corroborating signals means more confidence; zero signals means we know
 * nothing (weak / "unknown").
 */
function computeConfidence(signals: RiskSignal[]): Confidence {
  if (signals.some((s) => s.id === 'malicious_network_indicator')) return 'strong'
  if (signals.length >= 3) return 'strong'
  if (signals.length >= 1) return 'moderate'
  return 'weak'
}

function computeFamilyStatus(level: RiskLevel, signalCount: number): FamilyStatus {
  if (signalCount === 0) return 'unknown'
  switch (level) {
    case 'safe':
    case 'low':
      return 'safe'
    case 'medium':
      return 'needs_attention'
    case 'high':
    case 'critical':
      return 'dangerous'
  }
}

function recommendAction(level: RiskLevel, signals: RiskSignal[]): string {
  if (signals.some((s) => s.id === 'malicious_network_indicator')) {
    return 'Block network access and quarantine the file.'
  }
  switch (level) {
    case 'critical':
    case 'high':
      return 'Quarantine this application and review it before allowing it to run.'
    case 'medium':
      return 'Review this application; update it, or remove it if you do not recognize it.'
    case 'low':
      return 'Low risk — no action needed, but keep it up to date.'
    case 'safe':
      return 'No action needed.'
  }
}

/**
 * Core scoring function. Pure: same input → same output.
 */
export function assessRisk(input: RiskInput): RiskAssessment {
  const signals: RiskSignal[] = []

  for (const id of Object.keys(RISK_SIGNALS) as RiskSignalId[]) {
    const def = RISK_SIGNALS[id]
    if (input[def.key]) {
      signals.push({ id, weight: def.weight, evidence: def.evidence })
    }
  }

  // Most impactful evidence first; stable tiebreak keeps output deterministic.
  signals.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))

  const rawScore = signals.reduce((sum, s) => sum + s.weight, 0)
  const score = Math.max(0, Math.min(100, rawScore))
  const level = scoreToLevel(score)
  const confidence = computeConfidence(signals)
  const familyStatus = computeFamilyStatus(level, signals.length)
  const recommendedAction = recommendAction(level, signals)

  const explanation = signals.length
    ? signals.map((s) => s.evidence)
    : ['Not enough information was available to assess this item.']

  return { score, level, confidence, familyStatus, signals, explanation, recommendedAction }
}

/** A small allowlist of high-reputation publishers used by the desktop adapter. */
const TRUSTED_PUBLISHERS = [
  'microsoft',
  'microsoft corporation',
  'google',
  'google llc',
  'apple',
  'apple inc.',
  'mozilla',
  'mozilla corporation',
  'canonical',
  'the document foundation',
  'oracle',
  'adobe',
  'adobe inc.',
]

function isTrustedPublisher(publisher: string): boolean {
  return TRUSTED_PUBLISHERS.includes(publisher.trim().toLowerCase())
}

function isTempPath(p: string): boolean {
  if (!p) return false
  const lower = p.toLowerCase()
  return (
    /[\\/]temp[\\/]/.test(lower) ||
    /[\\/]tmp[\\/]/.test(lower) ||
    lower.includes('\\appdata\\local\\temp') ||
    lower.startsWith('/tmp/') ||
    lower.startsWith('/var/tmp/')
  )
}

const RECENT_BINARY_MS = 7 * 24 * 60 * 60 * 1000

/**
 * Map the limited fields available from a desktop installed-program inventory
 * into risk signals. Anything the platform cannot determine is left unknown
 * (false) rather than guessed — the engine simply has less evidence and reports
 * lower confidence. `now` is injectable for deterministic tests.
 */
export function riskInputFromInstalledProgram(
  program: InstalledProgram,
  now: number = Date.now(),
): RiskInput {
  const publisher = (program.publisher || '').trim()
  const trusted = publisher !== '' && isTrustedPublisher(publisher)

  let recentlyCreatedBinary = false
  if (program.installDate) {
    const t = Date.parse(program.installDate)
    if (!Number.isNaN(t)) recentlyCreatedBinary = now - t >= 0 && now - t <= RECENT_BINARY_MS
  }

  return {
    unknownPublisher: publisher === '',
    signedByTrustedPublisher: trusted,
    // MSI / Windows Installer packages come from a managed install database.
    trustedPackageManager: program.isWindowsInstaller === true,
    tempDirectoryBinary: isTempPath(program.installLocation || ''),
    recentlyCreatedBinary,
  }
}

/**
 * Assess a whole installed-program inventory and aggregate it into a report:
 * findings (worst-first), per-level and per-family counts, and a posture score
 * where 100 means nothing needs attention. Pure and deterministic given `now`.
 */
export function buildAppRiskReport(
  programs: InstalledProgram[],
  now: number = Date.now(),
): AppRiskReport {
  const generatedAt = new Date(now).toISOString()
  const findings: Finding[] = programs.map((p) => {
    const assessment = assessRisk(riskInputFromInstalledProgram(p, now))
    return toFinding(p.id, p.displayName, assessment, generatedAt)
  })

  findings.sort((a, b) => b.score - a.score)

  const summary: Partial<Record<RiskLevel, number>> = {}
  const familySummary: Partial<Record<FamilyStatus, number>> = {}
  for (const f of findings) {
    summary[f.level] = (summary[f.level] ?? 0) + 1
    familySummary[f.familyStatus] = (familySummary[f.familyStatus] ?? 0) + 1
  }

  const total = findings.length
  const dangerous = familySummary.dangerous ?? 0
  const needsAttention = familySummary.needs_attention ?? 0
  const postureScore = total === 0
    ? 100
    : Math.max(0, Math.min(100, Math.round(100 * (1 - (dangerous + 0.5 * needsAttention) / total))))

  return { findings, summary, familySummary, postureScore, total, generatedAt }
}

/** Build a structured finding from an assessment about a specific subject. */
export function toFinding(
  subjectId: string,
  subjectName: string,
  assessment: RiskAssessment,
  createdAt: string = new Date().toISOString(),
): Finding {
  return {
    id: `finding_${subjectId}`,
    type: 'application_risk',
    subjectId,
    subjectName,
    level: assessment.level,
    confidence: assessment.confidence,
    familyStatus: assessment.familyStatus,
    status: assessment.familyStatus === 'unknown' ? 'unknown' : 'potential_match',
    score: assessment.score,
    evidence: assessment.explanation,
    recommendedAction: assessment.recommendedAction,
    createdAt,
  }
}
