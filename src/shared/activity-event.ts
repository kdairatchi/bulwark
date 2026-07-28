/**
 * Bulwark Activity & Logs — shared event schema.
 *
 * Product rule: every event tells the user what happened, why it matters,
 * what caused it, what Bulwark did, and what they can safely do next.
 */

export const ACTIVITY_CATEGORIES = [
  'system',
  'security',
  'network',
  'malware',
  'vulnerability',
  'application',
  'startup',
  'privacy',
  'cleaning',
  'update',
  'compliance',
  'authentication',
  'remote_action',
  'policy',
  'billing',
  'agent',
  'diagnostic',
] as const

export type ActivityCategory = (typeof ACTIVITY_CATEGORIES)[number]

export type ActivitySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type ActivityStatus =
  | 'success'
  | 'warning'
  | 'failed'
  | 'blocked'
  | 'pending'
  | 'info'

/** Confirmed | Highly likely | Possible | Unknown */
export type ConfidenceLabel = 'confirmed' | 'highly_likely' | 'possible' | 'unknown'

export type ActivityLogMode = 'simple' | 'advanced' | 'raw'

export interface ActivityEvidenceItem {
  label: string
  value: string
  sensitive?: boolean
}

export interface ActivityCause {
  summary: string
  confidence: number
  confidenceLabel: ConfidenceLabel
  relatedEventIds: string[]
}

export interface ActivityRemediation {
  available: boolean
  automatic: boolean
  reversible: boolean
  actionId?: string
  /** Plain-language next step for the user. */
  nextStep: string
}

export interface ActivitySource {
  component: string
  process?: string
  application?: string
  ruleId?: string
  deviceName?: string
}

/**
 * Canonical activity event shown in Timeline / Table / Explain This.
 * Internal `eventType` uses dotted names: `network.connection.blocked`.
 */
export interface BulwarkEvent {
  id: string
  tenantId?: string
  deviceId: string | null
  timestamp: string

  category: ActivityCategory
  eventType: string
  severity: ActivitySeverity
  status: ActivityStatus

  /** Plain-language title, e.g. "Threat blocked" */
  title: string
  /** One-sentence summary of what happened */
  summary: string
  /** Why it matters (impact) */
  impact: string
  /** What Bulwark did */
  actionTaken: string

  source: ActivitySource
  evidence: ActivityEvidenceItem[]
  cause?: ActivityCause
  remediation?: ActivityRemediation

  /** Original payload for Raw mode */
  raw?: unknown
}

export interface ExplainLevels {
  simple: string
  technical: string
  evidence: ActivityEvidenceItem[]
}

export interface ErrorExplanation {
  title: string
  whatHappened: string
  whyItHappened: string
  whatWasAffected: string
  protectionStillActive: boolean
  severity: ActivitySeverity
  howToFix: string
  canAutoFix: boolean
  technicalDetails?: string
}
