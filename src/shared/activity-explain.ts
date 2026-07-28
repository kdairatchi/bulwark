/**
 * Plain-language + technical explain helpers for Bulwark activity events.
 * Explains deterministic evidence only — never invents a verdict.
 */

import type {
  ActivityCause,
  ActivityEvidenceItem,
  ActivitySeverity,
  BulwarkEvent,
  ConfidenceLabel,
  ErrorExplanation,
  ExplainLevels,
} from './activity-event'

export function confidenceLabelFromScore(score: number): ConfidenceLabel {
  if (score >= 0.95) return 'confirmed'
  if (score >= 0.8) return 'highly_likely'
  if (score >= 0.5) return 'possible'
  return 'unknown'
}

export function confidenceDisplay(label: ConfidenceLabel): string {
  switch (label) {
    case 'confirmed': return 'Confirmed'
    case 'highly_likely': return 'Highly likely'
    case 'possible': return 'Possible'
    case 'unknown': return 'Unknown'
  }
}

export function severityDisplay(severity: ActivitySeverity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

/** Build the three Explain This layers from a BulwarkEvent. */
export function explainEvent(event: BulwarkEvent): ExplainLevels {
  const app = event.source.application || event.source.process
  const simpleParts = [event.summary]
  if (event.actionTaken) simpleParts.push(event.actionTaken)
  if (event.remediation?.nextStep) simpleParts.push(event.remediation.nextStep)

  const techBits: string[] = [
    `eventType=${event.eventType}`,
    `severity=${event.severity}`,
    `status=${event.status}`,
  ]
  if (event.source.component) techBits.push(`component=${event.source.component}`)
  if (app) techBits.push(`process=${app}`)
  if (event.source.ruleId) techBits.push(`ruleId=${event.source.ruleId}`)
  if (event.cause) {
    techBits.push(
      `cause=${event.cause.summary}`,
      `confidence=${Math.round(event.cause.confidence * 100)}% (${confidenceDisplay(event.cause.confidenceLabel)})`,
    )
  }

  return {
    simple: simpleParts.filter(Boolean).join(' '),
    technical: techBits.join(' · '),
    evidence: event.evidence.length > 0
      ? event.evidence
      : [
          { label: 'Event type', value: event.eventType },
          { label: 'Severity', value: event.severity },
          { label: 'Status', value: event.status },
        ],
  }
}

/**
 * Map raw OS/Node errors into a user-facing explanation layer.
 * Never surface bare codes like EPERM alone.
 */
export function explainOsError(opts: {
  code?: string
  message?: string
  feature: string
  path?: string
}): ErrorExplanation {
  const code = (opts.code || '').toUpperCase()
  const msg = (opts.message || '').toLowerCase()
  const isPerm =
    code === 'EPERM'
    || code === 'EACCES'
    || msg.includes('operation not permitted')
    || msg.includes('access is denied')
    || msg.includes('permission denied')

  if (isPerm) {
    return {
      title: `${opts.feature} needs permission`,
      whatHappened: opts.path
        ? `Bulwark could not access “${opts.path}” because the operating system denied permission.`
        : `Bulwark could not complete ${opts.feature.toLowerCase()} because the operating system denied permission.`,
      whyItHappened: 'The target is protected, or Bulwark is running without administrator privileges.',
      whatWasAffected: `${opts.feature} for the protected item was skipped.`,
      protectionStillActive: true,
      severity: 'medium',
      howToFix: 'Restart Bulwark as administrator, or skip this folder and continue.',
      canAutoFix: false,
      technicalDetails: [opts.code, opts.message].filter(Boolean).join(': ') || undefined,
    }
  }

  return {
    title: `${opts.feature} incomplete`,
    whatHappened: opts.message
      ? `Bulwark could not finish ${opts.feature.toLowerCase()}: ${opts.message}`
      : `Bulwark could not finish ${opts.feature.toLowerCase()}.`,
    whyItHappened: 'An unexpected error interrupted the operation.',
    whatWasAffected: `Results from ${opts.feature.toLowerCase()} may be incomplete.`,
    protectionStillActive: true,
    severity: 'low',
    howToFix: 'Retry the action. If it keeps failing, open Technical Details and share them with support.',
    canAutoFix: false,
    technicalDetails: [opts.code, opts.message].filter(Boolean).join(': ') || undefined,
  }
}

export function formatEventCardTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return iso
  }
}

/** One-line card header: "10:42 PM — Threat blocked" */
export function formatEventHeadline(event: BulwarkEvent): string {
  try {
    const t = new Date(event.timestamp).toLocaleTimeString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    })
    return `${t} — ${event.title}`
  } catch {
    return event.title
  }
}

export function buildCause(
  summary: string,
  confidence: number,
  relatedEventIds: string[] = [],
): ActivityCause {
  return {
    summary,
    confidence,
    confidenceLabel: confidenceLabelFromScore(confidence),
    relatedEventIds,
  }
}

/** Group events into day buckets for Activity timeline headers. */
export function groupEventsByDay<T extends { timestamp: string }>(
  events: T[],
  now = new Date(),
): Array<{ key: string; label: string; events: T[] }> {
  const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const today = startOfDay(now)
  const yesterday = today - 86_400_000
  const buckets = new Map<string, { label: string; events: T[]; sort: number }>()

  for (const event of events) {
    const t = new Date(event.timestamp)
    const day = startOfDay(t)
    let key: string
    let label: string
    if (Number.isNaN(day)) {
      key = 'unknown'
      label = 'Unknown date'
    } else if (day === today) {
      key = 'today'
      label = 'Today'
    } else if (day === yesterday) {
      key = 'yesterday'
      label = 'Yesterday'
    } else {
      key = String(day)
      label = t.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })
    }
    const bucket = buckets.get(key) || { label, events: [], sort: Number.isNaN(day) ? 0 : day }
    bucket.events.push(event)
    buckets.set(key, bucket)
  }

  return [...buckets.entries()]
    .sort((a, b) => b[1].sort - a[1].sort)
    .map(([key, b]) => ({ key, label: b.label, events: b.events }))
}

export function redactEvidence(
  items: ActivityEvidenceItem[],
  opts: { hideIps?: boolean; hidePaths?: boolean; hideApps?: boolean } = {},
): ActivityEvidenceItem[] {
  return items.map((item) => {
    if (!item.sensitive && !opts.hideIps && !opts.hidePaths && !opts.hideApps) return item
    let value = item.value
    if (opts.hideIps || item.sensitive) {
      value = value.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, 'x.x.x.x')
    }
    if (opts.hidePaths) {
      value = value.replace(/(?:\/[\w.-]+)+/g, '/…').replace(/[A-Za-z]:\\(?:[^\\/]+\\)*/g, '…\\')
    }
    if (opts.hideApps && /process|application|package/i.test(item.label)) {
      value = '[redacted]'
    }
    return { ...item, value }
  })
}
