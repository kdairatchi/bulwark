// Transparent, deterministic risk model shared across the desktop agent, CLI,
// and (later) the Android agent and cloud control plane.
//
// Design rule (see docs/threat-model/README.md#risk-scoring): a deterministic,
// weighted signal engine produces the score, evidence, and confidence. An LLM
// may only *explain* a result in plain language — it never decides whether
// something is malicious, and it never changes the score.

/** Ordered from least to most severe. */
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical'

/** How much corroborating evidence backs the assessment. */
export type Confidence = 'weak' | 'moderate' | 'strong'

/**
 * Plain-language status for "family mode" — the only thing a non-technical user
 * should need to read. The detailed evidence stays under an advanced view.
 */
export type FamilyStatus = 'safe' | 'needs_attention' | 'dangerous' | 'unknown'

/** Lifecycle status of a finding (mirrors the vulnerability finding statuses). */
export type FindingStatus =
  | 'confirmed_affected'
  | 'likely_affected'
  | 'potential_match'
  | 'not_exploitable'
  | 'fixed'
  | 'accepted_risk'
  | 'false_positive'
  | 'unknown'

/**
 * Deterministic signals. Positive weights raise risk; negative weights lower it.
 * Weights come directly from the product spec's example scoring model and are the
 * single source of truth (see RISK_SIGNALS in risk-engine.ts).
 */
export type RiskSignalId =
  | 'unsigned_executable'
  | 'unknown_publisher'
  | 'runs_at_startup'
  | 'requests_admin'
  | 'malicious_network_indicator'
  | 'unknown_install_source'
  | 'recently_created_binary'
  | 'temp_directory_binary'
  | 'persistence_mechanism'
  | 'signed_by_trusted_publisher'
  | 'trusted_package_manager'
  | 'high_prevalence'

/** A signal that fired, with the human-readable evidence for it. */
export interface RiskSignal {
  id: RiskSignalId
  /** Signed weight applied to the score. */
  weight: number
  /** Plain-language evidence line shown to the user. */
  evidence: string
}

/**
 * Booleans describing what is known about a subject. Everything defaults to
 * "unknown" (false); adapters (e.g. from an installed program) fill in what the
 * platform can actually determine.
 */
export interface RiskInput {
  unsignedExecutable?: boolean
  unknownPublisher?: boolean
  runsAtStartup?: boolean
  requestsAdmin?: boolean
  maliciousNetworkIndicator?: boolean
  unknownInstallSource?: boolean
  recentlyCreatedBinary?: boolean
  tempDirectoryBinary?: boolean
  persistenceMechanism?: boolean
  signedByTrustedPublisher?: boolean
  trustedPackageManager?: boolean
  highPrevalence?: boolean
}

/** The transparent result: score is secondary to evidence + confidence. */
export interface RiskAssessment {
  /** 0–100 risk points (clamped). Never shown more prominently than evidence. */
  score: number
  level: RiskLevel
  confidence: Confidence
  familyStatus: FamilyStatus
  /** Signals that fired, ordered by absolute weight (most impactful first). */
  signals: RiskSignal[]
  /** Plain-language "why" bullets, built deterministically from the signals. */
  explanation: string[]
  /** Concrete next step for the user. */
  recommendedAction: string
}

/** A structured finding produced from an assessment about a specific subject. */
export interface Finding {
  id: string
  type: 'application_risk'
  subjectId: string
  subjectName: string
  level: RiskLevel
  confidence: Confidence
  familyStatus: FamilyStatus
  status: FindingStatus
  score: number
  evidence: string[]
  recommendedAction: string
  createdAt: string
}
