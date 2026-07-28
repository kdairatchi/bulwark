import { describe, it, expect } from 'vitest'
import {
  buildCause,
  confidenceLabelFromScore,
  confidenceDisplay,
  explainEvent,
  explainOsError,
  formatEventHeadline,
  groupEventsByDay,
  redactEvidence,
} from './activity-explain'
import type { BulwarkEvent } from './activity-event'

function sampleEvent(overrides: Partial<BulwarkEvent> = {}): BulwarkEvent {
  return {
    id: 'evt_1',
    deviceId: 'dev_1',
    timestamp: '2026-07-28T22:42:00.000Z',
    category: 'network',
    eventType: 'network.connection.blocked',
    severity: 'medium',
    status: 'blocked',
    title: 'Threat blocked',
    summary: 'A connection toward evil.example was blocked.',
    impact: 'Malicious traffic was stopped.',
    actionTaken: 'Bulwark sinkholed the name on the local DoT resolver.',
    source: { component: 'dns-resolver', application: 'evil.example', ruleId: 'network.dns.blocked' },
    evidence: [{ label: 'Domain', value: 'evil.example' }],
    cause: buildCause('Domain matched a blocklist', 0.85),
    remediation: {
      available: true,
      automatic: false,
      reversible: true,
      nextStep: 'Remove the domain from the block list if this was a false positive.',
    },
    ...overrides,
  }
}

describe('activity-explain', () => {
  it('maps confidence scores to labels', () => {
    expect(confidenceLabelFromScore(0.99)).toBe('confirmed')
    expect(confidenceLabelFromScore(0.85)).toBe('highly_likely')
    expect(confidenceLabelFromScore(0.6)).toBe('possible')
    expect(confidenceLabelFromScore(0.1)).toBe('unknown')
    expect(confidenceDisplay('highly_likely')).toBe('Highly likely')
  })

  it('builds three Explain This layers without inventing verdicts', () => {
    const levels = explainEvent(sampleEvent())
    expect(levels.simple).toContain('evil.example')
    expect(levels.simple).toContain('false positive')
    expect(levels.technical).toContain('eventType=network.connection.blocked')
    expect(levels.technical).toContain('Highly likely')
    expect(levels.evidence.some((e) => e.label === 'Domain')).toBe(true)
  })

  it('explains EPERM in plain language (never bare code alone)', () => {
    const ex = explainOsError({
      code: 'EPERM',
      message: 'operation not permitted',
      feature: 'Cleaner',
      path: '/root/secret',
    })
    expect(ex.title).toMatch(/permission/i)
    expect(ex.whatHappened).toContain('/root/secret')
    expect(ex.whatHappened).not.toBe('EPERM')
    expect(ex.protectionStillActive).toBe(true)
    expect(ex.technicalDetails).toContain('EPERM')
    expect(ex.howToFix).toMatch(/administrator/i)
  })

  it('formats card headlines with time + title', () => {
    const headline = formatEventHeadline(sampleEvent())
    expect(headline).toContain('Threat blocked')
    expect(headline).toContain('—')
  })

  it('redacts IPs and paths when requested', () => {
    const redacted = redactEvidence(
      [
        { label: 'Remote', value: '10.0.0.5 connected to /var/log/syslog' },
        { label: 'Process', value: 'chrome', sensitive: true },
      ],
      { hideIps: true, hidePaths: true, hideApps: true },
    )
    expect(redacted[0].value).toContain('x.x.x.x')
    expect(redacted[0].value).toContain('/…')
    expect(redacted[1].value).toBe('[redacted]')
  })

  it('groups events into Today / Yesterday / date buckets', () => {
    const now = new Date('2026-07-28T15:00:00.000Z')
    const groups = groupEventsByDay(
      [
        { id: '1', timestamp: '2026-07-28T12:00:00.000Z' },
        { id: '2', timestamp: '2026-07-27T12:00:00.000Z' },
        { id: '3', timestamp: '2026-07-20T12:00:00.000Z' },
      ],
      now,
    )
    expect(groups.map((g) => g.label)).toEqual([
      'Today',
      'Yesterday',
      expect.stringMatching(/Jul/),
    ])
    expect(groups[0].events).toHaveLength(1)
  })
})
