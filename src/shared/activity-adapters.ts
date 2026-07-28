/**
 * Adapt existing cloud/agent payloads into BulwarkEvent cards.
 */

import type { BulwarkEvent } from './activity-event'
import { buildCause } from './activity-explain'
import { coerceRiskLevel, explainFinding } from './finding'
import type { UnifiedFinding } from './finding'

export interface AlertLike {
  id: string
  severity: string
  type: string
  subject: string
  detail?: string | null
  at: string
  deviceId: string | null
  acknowledged: boolean
}

export interface NetworkEventLike {
  id: string
  deviceId: string
  type: string
  at: string
  subject: string | null
  detail: string | null
  metadata?: Record<string, unknown>
}

function mapSeverity(raw: string): BulwarkEvent['severity'] {
  const s = raw.toLowerCase()
  if (s === 'critical') return 'critical'
  if (s === 'high') return 'high'
  if (s === 'medium') return 'medium'
  if (s === 'low') return 'low'
  return 'info'
}

/** Dashboard computed alerts → activity cards. */
export function alertToBulwarkEvent(
  alert: AlertLike,
  opts: { deviceName?: string } = {},
): BulwarkEvent {
  const type = alert.type
  if (type === 'kev_finding') {
    return {
      id: alert.id,
      deviceId: alert.deviceId,
      timestamp: alert.at,
      category: 'vulnerability',
      eventType: 'vulnerability.detected',
      severity: mapSeverity(alert.severity),
      status: alert.acknowledged ? 'success' : 'warning',
      title: 'Vulnerability matched',
      summary: `${alert.subject} matched a known exploited vulnerability${alert.detail ? `: ${alert.detail}` : '.'}`,
      impact: 'This software may be remotely exploitable until it is updated.',
      actionTaken: 'Bulwark recorded the finding on the device security score.',
      source: {
        component: 'kev-matcher',
        application: alert.subject,
        ruleId: 'vuln.kev.match',
        deviceName: opts.deviceName,
      },
      evidence: [
        { label: 'CVE / subject', value: alert.subject },
        ...(alert.detail ? [{ label: 'Detail', value: alert.detail }] : []),
        { label: 'Alert type', value: type },
      ],
      cause: buildCause('Installed software version matched a CISA KEV / catalog entry', 0.9),
      remediation: {
        available: true,
        automatic: false,
        reversible: false,
        nextStep: 'Open Findings, review the KEV fix recommendation, and update the package.',
      },
      raw: alert,
    }
  }

  if (type === 'isolation') {
    return {
      id: alert.id,
      deviceId: alert.deviceId,
      timestamp: alert.at,
      category: 'policy',
      eventType: 'policy.isolation.enabled',
      severity: 'high',
      status: 'blocked',
      title: 'Device isolated',
      summary: opts.deviceName
        ? `${opts.deviceName} is in emergency isolation — only allowlisted domains resolve.`
        : 'A device is in emergency isolation — only allowlisted domains resolve.',
      impact: 'Most internet access on this device is blocked until isolation is cleared.',
      actionTaken: 'Bulwark applied allowlist DNS policy on the loopback resolver.',
      source: {
        component: 'device-policy-enforcer',
        ruleId: 'policy.isolate',
        deviceName: opts.deviceName,
      },
      evidence: [
        { label: 'Subject', value: alert.subject },
        ...(alert.detail ? [{ label: 'Detail', value: alert.detail }] : []),
      ],
      cause: buildCause('Parent/dashboard isolation or remote ISOLATE_DEVICE command', 0.85),
      remediation: {
        available: true,
        automatic: false,
        reversible: true,
        actionId: 'clear_isolation',
        nextStep: 'When safe, use Clear isolation on the parent panel.',
      },
      raw: alert,
    }
  }

  if (type === 'dns_blocked') {
    return {
      id: alert.id,
      deviceId: alert.deviceId,
      timestamp: alert.at,
      category: 'network',
      eventType: 'network.connection.blocked',
      severity: mapSeverity(alert.severity) === 'info' ? 'medium' : mapSeverity(alert.severity),
      status: 'blocked',
      title: 'Threat blocked',
      summary: alert.subject
        ? `A connection toward ${alert.subject} was blocked by Network Guard / DNS policy.`
        : 'A suspicious DNS lookup was blocked.',
      impact: 'Malicious or policy-denied traffic was stopped before it completed.',
      actionTaken: 'Bulwark sinkholed the name on the local DoT resolver.',
      source: {
        component: 'dns-resolver',
        application: alert.subject || undefined,
        ruleId: 'network.dns.blocked',
        deviceName: opts.deviceName,
      },
      evidence: [
        { label: 'Domain', value: alert.subject || '—' },
        ...(alert.detail ? [{ label: 'Via', value: alert.detail }] : []),
      ],
      cause: buildCause(
        alert.detail || 'Domain matched a blocklist, isolation allowlist miss, or remote BLOCK_DOMAIN',
        0.8,
      ),
      remediation: {
        available: true,
        automatic: false,
        reversible: true,
        nextStep: 'If this was a false positive, remove the domain from the block list or clear isolation.',
      },
      raw: alert,
    }
  }

  if (type === 'breach') {
    return {
      id: alert.id,
      deviceId: null,
      timestamp: alert.at,
      category: 'security',
      eventType: 'security.breach.detected',
      severity: 'high',
      status: alert.acknowledged ? 'success' : 'warning',
      title: 'Email breach detected',
      summary: alert.subject
        ? `A monitored email appeared in the ${alert.subject} breach.`
        : 'A monitored email appeared in a known data breach.',
      impact: 'Credentials or personal data from that site may be exposed.',
      actionTaken: 'Bulwark added the exposure to your breach monitor list.',
      source: {
        component: 'breach-monitors',
        ruleId: 'security.breach.hibp',
      },
      evidence: [
        { label: 'Breach', value: alert.subject },
        ...(alert.detail ? [{ label: 'Detail', value: alert.detail }] : []),
      ],
      cause: buildCause('Have I Been Pwned / stub catalog match for a monitored address', 0.88),
      remediation: {
        available: true,
        automatic: false,
        reversible: false,
        nextStep: 'Change the password on that site, enable 2FA, and mark the breach reviewed.',
      },
      raw: alert,
    }
  }

  return {
    id: alert.id,
    deviceId: alert.deviceId,
    timestamp: alert.at,
    category: 'diagnostic',
    eventType: `alert.${type}`,
    severity: mapSeverity(alert.severity),
    status: 'info',
    title: 'Security alert',
    summary: alert.subject || type,
    impact: 'Review this alert on the parent dashboard.',
    actionTaken: 'Bulwark recorded the alert.',
    source: { component: 'alerts', deviceName: opts.deviceName },
    evidence: [
      { label: 'Type', value: type },
      { label: 'Subject', value: alert.subject },
    ],
    remediation: {
      available: false,
      automatic: false,
      reversible: false,
      nextStep: 'Open the parent alerts list for details.',
    },
    raw: alert,
  }
}

/** Local scan/clean history → activity cards. */
export function scanHistoryToBulwarkEvent(entry: {
  id: string
  type: string
  timestamp: string
  duration: number
  totalItemsFound: number
  totalItemsCleaned: number
  totalItemsSkipped: number
  totalSpaceSaved: number
  errorCount: number
  scheduled?: boolean
  scheduleName?: string
}): BulwarkEvent {
  const label = entry.type.replace(/-/g, ' ')
  const failed = entry.errorCount > 0
  const cleaned = entry.totalItemsCleaned > 0
  return {
    id: entry.id,
    deviceId: null,
    timestamp: entry.timestamp,
    category: entry.type === 'malware' || entry.type === 'cve-scan' ? 'security' : 'cleaning',
    eventType: `cleaning.${entry.type}.${cleaned ? 'completed' : 'scanned'}`,
    severity: failed ? 'medium' : cleaned ? 'info' : 'info',
    status: failed ? 'warning' : cleaned ? 'success' : 'info',
    title: cleaned ? `${label} cleaned` : `${label} scan`,
    summary: cleaned
      ? `Removed ${entry.totalItemsCleaned.toLocaleString()} item(s)`
        + (entry.totalSpaceSaved > 0
          ? ` and freed about ${Math.round(entry.totalSpaceSaved / (1024 * 1024))} MB.`
          : '.')
      : `Found ${entry.totalItemsFound.toLocaleString()} item(s); nothing was cleaned yet.`,
    impact: failed
      ? `${entry.errorCount} error(s) occurred — some items may still remain.`
      : cleaned
        ? 'Disk space and clutter were reduced on this device.'
        : 'No files were changed; this was a scan-only result.',
    actionTaken: cleaned
      ? 'Bulwark deleted or cleaned the selected items.'
      : 'Bulwark scanned and recorded the results.',
    source: {
      component: entry.scheduled ? 'scheduler' : 'cleaner',
      ruleId: entry.type,
      process: entry.scheduleName,
    },
    evidence: [
      { label: 'Type', value: entry.type },
      { label: 'Found', value: String(entry.totalItemsFound) },
      { label: 'Cleaned', value: String(entry.totalItemsCleaned) },
      { label: 'Skipped', value: String(entry.totalItemsSkipped) },
      { label: 'Errors', value: String(entry.errorCount) },
      { label: 'Duration (ms)', value: String(entry.duration) },
    ],
    cause: entry.scheduled
      ? buildCause(`Scheduled task${entry.scheduleName ? `: ${entry.scheduleName}` : ''}`, 0.95)
      : buildCause('Manual scan or clean from the desktop app', 0.95),
    remediation: {
      available: failed,
      automatic: false,
      reversible: false,
      nextStep: failed
        ? 'Open Technical Details, retry the scan, or run as administrator if permission errors appear.'
        : 'No action needed unless you want to clean more categories.',
    },
    raw: entry,
  }
}

/** Device network events → activity cards. */
export function networkEventToBulwarkEvent(
  evt: NetworkEventLike,
  opts: { deviceName?: string } = {},
): BulwarkEvent {
  const type = evt.type
  if (type === 'dns_blocked') {
    return alertToBulwarkEvent({
      id: `alert_dns_${evt.id}`,
      severity: 'medium',
      type: 'dns_blocked',
      subject: evt.subject || 'unknown',
      detail: evt.detail,
      at: evt.at,
      deviceId: evt.deviceId,
      acknowledged: false,
    }, opts)
  }
  if (type === 'isolation_enabled' || type === 'isolation_cleared') {
    const enabled = type === 'isolation_enabled'
    return {
      id: evt.id,
      deviceId: evt.deviceId,
      timestamp: evt.at,
      category: 'policy',
      eventType: enabled ? 'policy.isolation.enabled' : 'policy.isolation.cleared',
      severity: enabled ? 'high' : 'info',
      status: enabled ? 'blocked' : 'success',
      title: enabled ? 'Device isolated' : 'Isolation cleared',
      summary: enabled
        ? 'Emergency isolation was turned on for this device.'
        : 'Emergency isolation was cleared; normal DNS filtering resumed.',
      impact: enabled
        ? 'Only allowlisted domains resolve until isolation is cleared.'
        : 'Full DNS resolution is available again under current policy.',
      actionTaken: enabled
        ? 'Bulwark switched the loopback resolver to allowlist mode.'
        : 'Bulwark restored blocklist mode on the loopback resolver.',
      source: {
        component: 'device-policy-enforcer',
        deviceName: opts.deviceName,
        ruleId: type,
      },
      evidence: [
        { label: 'Event', value: type },
        ...(evt.subject ? [{ label: 'Subject', value: evt.subject }] : []),
      ],
      raw: evt,
    }
  }

  return {
    id: evt.id,
    deviceId: evt.deviceId,
    timestamp: evt.at,
    category: 'agent',
    eventType: `agent.${type}`,
    severity: 'info',
    status: 'info',
    title: type.replace(/_/g, ' '),
    summary: evt.detail || evt.subject || type,
    impact: 'Informational device event.',
    actionTaken: 'Logged by the device agent.',
    source: { component: 'device-agent', deviceName: opts.deviceName },
    evidence: [
      { label: 'Type', value: type },
      ...(evt.subject ? [{ label: 'Subject', value: evt.subject }] : []),
      ...(evt.detail ? [{ label: 'Detail', value: evt.detail }] : []),
    ],
    raw: evt,
  }
}

/** UnifiedFinding → activity card (for Activity / parent surfaces). */
export function findingToBulwarkEvent(
  finding: UnifiedFinding,
  opts: { deviceId?: string | null; deviceName?: string } = {},
): BulwarkEvent {
  const explained = explainFinding(finding)
  const category: BulwarkEvent['category'] =
    finding.type === 'malware' || finding.category === 'malware' || finding.category === 'lolbin' ? 'malware'
      : finding.type === 'vulnerability' || ['kev', 'osv', 'cve'].includes(finding.category) ? 'vulnerability'
        : finding.type === 'network' || finding.category === 'network' ? 'network'
          : finding.type === 'privacy' || finding.category === 'privacy' ? 'privacy'
            : finding.type === 'application_risk' || finding.category === 'risk' ? 'application'
              : 'security'

  const level = coerceRiskLevel(finding.level)

  return {
    id: finding.id,
    deviceId: opts.deviceId ?? null,
    timestamp: finding.createdAt,
    category,
    eventType: `finding.${finding.category || finding.type}`,
    severity: level === 'safe' ? 'info' : level,
    status: finding.status === 'fixed' || finding.status === 'false_positive' || finding.status === 'accepted_risk'
      ? 'success'
      : 'warning',
    title: finding.type === 'malware' ? 'Malware finding'
      : finding.type === 'vulnerability' ? 'Vulnerability finding'
        : finding.type === 'network' ? 'Network finding'
          : finding.type === 'privacy' ? 'Privacy finding'
            : 'Security finding',
    summary: `${finding.subjectName}: ${explained.why}`,
    impact: explained.confidence,
    actionTaken: 'Bulwark recorded a structured finding for review.',
    source: {
      component: 'findings',
      application: finding.subjectName,
      ruleId: finding.reason.slice(0, 80),
      deviceName: opts.deviceName,
    },
    evidence: [
      { label: 'Subject', value: finding.subjectName },
      { label: 'Level', value: finding.level },
      { label: 'Status', value: finding.status },
      { label: 'Category', value: finding.category },
      ...(finding.evidence || []).slice(0, 4).map((v, i) => ({ label: `Evidence ${i + 1}`, value: v })),
    ],
    cause: buildCause(
      explained.why,
      finding.status === 'confirmed_affected' ? 0.95
        : finding.status === 'likely_affected' ? 0.85
          : 0.6,
    ),
    remediation: {
      available: true,
      automatic: false,
      reversible: finding.type === 'privacy' || finding.type === 'network',
      nextStep: explained.nextStep,
    },
    raw: finding,
  }
}

