/**
 * Plain-language explainers for parent-panel network / device events.
 * Deterministic rephrasing of event type + subject — no invented telemetry.
 */

export type ParentEventExplanation = {
  title: string
  why: string[]
  recommended: string
  accent: string
  severity: 'info' | 'attention' | 'critical'
}

const TYPE_COPY: Record<string, { title: string; why: string; recommended: string; severity: ParentEventExplanation['severity'] }> = {
  dns_block: {
    title: 'DNS block',
    why: 'A domain lookup was blocked by Network Guard or parent DNS policy on this device.',
    recommended: 'If this was unexpected, check blocked-domain rules or clear isolation if the device is isolated.',
    severity: 'attention',
  },
  dns_allow: {
    title: 'DNS allow',
    why: 'A domain lookup was allowed through the device DNS policy.',
    recommended: 'No action needed unless you want to tighten rules for this destination.',
    severity: 'info',
  },
  isolate: {
    title: 'Isolation applied',
    why: 'Emergency isolation was applied so most internet destinations stop resolving.',
    recommended: 'Watch heartbeats. Clear isolation from parent controls when the risk has passed.',
    severity: 'critical',
  },
  isolation: {
    title: 'Isolation event',
    why: 'An isolation-related change was recorded for this device.',
    recommended: 'Confirm whether the device should stay isolated, then clear when safe.',
    severity: 'critical',
  },
  clear_isolate: {
    title: 'Isolation cleared',
    why: 'Emergency isolation was cleared and normal DNS policy should resume.',
    recommended: 'Run a quick health or malware scan if you want extra reassurance.',
    severity: 'info',
  },
  network_block: {
    title: 'Network block',
    why: 'An outbound connection matched a block rule or threat indicator.',
    recommended: 'Review Network Guard rules and recent connections on the device.',
    severity: 'attention',
  },
  network_alert: {
    title: 'Network alert',
    why: 'A destination matched an alert-level indicator (not necessarily blocked).',
    recommended: 'Check the destination in Network Guard and tighten rules if needed.',
    severity: 'attention',
  },
  heartbeat: {
    title: 'Heartbeat',
    why: 'The device checked in with Bulwrk cloud — it is reachable for parent commands.',
    recommended: 'No action needed.',
    severity: 'info',
  },
  enroll: {
    title: 'Device enrolled',
    why: 'This device completed family pairing and enrolled for parent controls.',
    recommended: 'Request a first scan from parent controls if you have not already.',
    severity: 'info',
  },
  scan: {
    title: 'Scan activity',
    why: 'A remote or local scan-related event was recorded for this device.',
    recommended: 'Open Findings if anything new needs review.',
    severity: 'info',
  },
  command: {
    title: 'Remote command',
    why: 'A parent command was processed on this device.',
    recommended: 'Check History or Findings for the outcome if you expected a scan or isolate.',
    severity: 'info',
  },
}

function normalizeType(type: string): string {
  return type.trim().toLowerCase().replace(/[\s-]+/g, '_')
}

function matchTypeKey(type: string): string | null {
  const n = normalizeType(type)
  if (TYPE_COPY[n]) return n
  // Prefer longer / more specific contains matches
  const ranked = Object.keys(TYPE_COPY).sort((a, b) => b.length - a.length)
  for (const k of ranked) {
    if (n === k || n.includes(k)) return k
  }
  if (n.includes('isolat') && (n.includes('clear') || n.includes('remove') || n.includes('lift'))) return 'clear_isolate'
  if (n.includes('isolat')) return 'isolate'
  if (n.includes('dns') && n.includes('block')) return 'dns_block'
  if (n.includes('dns') && n.includes('allow')) return 'dns_allow'
  if (n.includes('block')) return 'network_block'
  if (n.includes('alert')) return 'network_alert'
  if (n.includes('heartbeat')) return 'heartbeat'
  if (n.includes('enroll') || n.includes('pair')) return 'enroll'
  if (n.includes('scan')) return 'scan'
  if (n.includes('command') || n.endsWith('_cmd') || n.startsWith('cmd_')) return 'command'
  return null
}

const SEVERITY_ACCENT: Record<ParentEventExplanation['severity'], string> = {
  info: '#a1a1aa',
  attention: '#fbbf24',
  critical: '#f87171',
}

/** Explain a parent-panel device/network event for family-readable UI. */
export function explainParentEvent(input: {
  type: string
  subject?: string | null
  detail?: string | null
}): ParentEventExplanation {
  const key = matchTypeKey(input.type)
  const base = key ? TYPE_COPY[key] : null
  const why: string[] = []

  if (base) {
    why.push(base.why)
  } else {
    why.push(`Bulwrk recorded a “${input.type.replace(/_/g, ' ')}” event on this device.`)
  }

  const subject = (input.subject || '').trim()
  if (subject) why.push(`Related to: ${subject.slice(0, 160)}`)

  const detail = (input.detail || '').trim()
  if (detail) why.push(detail.slice(0, 200))

  const severity = base?.severity ?? (/block|isolat|threat|malware/i.test(input.type) ? 'attention' : 'info')

  return {
    title: base?.title ?? input.type.replace(/_/g, ' '),
    why: why.slice(0, 5),
    recommended: base?.recommended ?? 'Review parent findings and Network Guard if this looks unexpected.',
    accent: SEVERITY_ACCENT[severity],
    severity,
  }
}
