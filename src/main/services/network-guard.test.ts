import { describe, it, expect } from 'vitest'
import {
  buildIndicatorIndex,
  matchDestination,
  decide,
  evaluateDestination,
  normalizeDomain,
  isIpAddress,
  categoryDecision,
  hasBlockingEvent,
  sanitizeIndicators,
} from './network-guard'
import type { ThreatIndicator } from '../../shared/network-guard'

const INDICATORS: ThreatIndicator[] = [
  { value: 'evil-c2.example', type: 'domain', category: 'c2', source: 'demo', confidence: 0.99 },
  { value: 'phish.example', type: 'domain', category: 'phishing' },
  { value: 'proxy.example', type: 'domain', category: 'residential_proxy' },
  { value: '203.0.113.7', type: 'ip', category: 'botnet' },
  { value: '198.51.100.0/24', type: 'cidr', category: 'cryptomining' },
]

const now = Date.parse('2026-07-27T18:30:00Z')
const index = buildIndicatorIndex(INDICATORS)

describe('network-guard · normalization', () => {
  it('lowercases, strips trailing dot and port', () => {
    expect(normalizeDomain('EVIL-C2.Example.')).toBe('evil-c2.example')
    expect(normalizeDomain('host.example:443')).toBe('host.example')
  })

  it('detects IPv4 and IPv6 addresses', () => {
    expect(isIpAddress('203.0.113.7')).toBe(true)
    expect(isIpAddress('2001:db8::1')).toBe(true)
    expect(isIpAddress('evil.example')).toBe(false)
  })
})

describe('network-guard · matching', () => {
  it('matches an exact domain', () => {
    const m = matchDestination('evil-c2.example', index)
    expect(m?.via).toBe('domain')
    expect(m?.indicator.category).toBe('c2')
  })

  it('matches a subdomain via its parent indicator', () => {
    const m = matchDestination('cdn.assets.phish.example', index)
    expect(m?.via).toBe('parent-domain')
    expect(m?.matchedValue).toBe('phish.example')
  })

  it('does not match an unrelated domain that merely ends similarly', () => {
    expect(matchDestination('notphish.example', index)).toBeNull()
    expect(matchDestination('example', index)).toBeNull()
  })

  it('matches an exact IP', () => {
    const m = matchDestination('203.0.113.7', index)
    expect(m?.via).toBe('ip')
    expect(m?.indicator.category).toBe('botnet')
  })

  it('matches an IP inside a CIDR block', () => {
    const m = matchDestination('198.51.100.42', index)
    expect(m?.via).toBe('cidr')
    expect(m?.matchedValue).toBe('198.51.100.0/24')
    expect(m?.indicator.category).toBe('cryptomining')
  })

  it('returns null for a clean destination', () => {
    expect(matchDestination('good.example', index)).toBeNull()
    expect(matchDestination('8.8.8.8', index)).toBeNull()
  })
})

describe('network-guard · decision policy', () => {
  it('prefers the indicator confidence over the category default', () => {
    const m = matchDestination('evil-c2.example', index)!
    expect(decide(m)).toMatchObject({ decision: 'block', reason: 'known_c2', confidence: 0.99, category: 'c2' })
  })

  it('falls back to the category default confidence', () => {
    const m = matchDestination('phish.example', index)!
    expect(decide(m)).toMatchObject({ decision: 'block', reason: 'phishing', confidence: 0.9 })
  })

  it('alerts (not blocks) for residential proxy', () => {
    const m = matchDestination('proxy.example', index)!
    expect(decide(m).decision).toBe('alert')
    expect(categoryDecision('residential_proxy')).toBe('alert')
    expect(categoryDecision('c2')).toBe('block')
  })
})

describe('network-guard · evaluateDestination (full pipeline)', () => {
  it('produces a metadata-only block event with a fixed timestamp', () => {
    const ev = evaluateDestination({ destination: 'evil-c2.example', port: 443, protocol: 'tcp' }, index, now)
    expect(ev).toEqual({
      destination: 'evil-c2.example',
      destinationType: 'domain',
      port: 443,
      protocol: 'tcp',
      decision: 'block',
      reason: 'known_c2',
      category: 'c2',
      confidence: 0.99,
      matchedIndicator: 'evil-c2.example',
      timestamp: '2026-07-27T18:30:00.000Z',
    })
  })

  it('allows a clean destination with zero confidence and no category', () => {
    const ev = evaluateDestination({ destination: 'good.example' }, index, now)
    expect(ev.decision).toBe('allow')
    expect(ev.reason).toBe('no_match')
    expect(ev.confidence).toBe(0)
    expect(ev.category).toBeUndefined()
    expect(ev.matchedIndicator).toBeUndefined()
  })

  it('classifies an IP destination type', () => {
    const ev = evaluateDestination({ destination: '203.0.113.7' }, index, now)
    expect(ev.destinationType).toBe('ip')
    expect(ev.decision).toBe('block')
  })

  it('is deterministic', () => {
    const input = { destination: '198.51.100.42', port: 8333, protocol: 'tcp' as const }
    expect(evaluateDestination(input, index, now)).toEqual(evaluateDestination(input, index, now))
  })
})

describe('network-guard · sanitizeIndicators', () => {
  it('keeps valid entries and drops malformed ones', () => {
    const raw = [
      { value: 'a.example', type: 'domain', category: 'c2', confidence: 0.9, source: 'feed' },
      { value: '', type: 'domain', category: 'c2' }, // empty value
      { value: 'b.example', type: 'bogus', category: 'c2' }, // bad type
      { value: 'c.example', type: 'domain', category: 'not-a-category' }, // bad category
      { value: 'd.example', type: 'domain', category: 'phishing', confidence: 5 }, // out-of-range confidence dropped
      'not-an-object',
    ]
    const clean = sanitizeIndicators(raw)
    expect(clean).toHaveLength(2)
    expect(clean[0]).toEqual({ value: 'a.example', type: 'domain', category: 'c2', source: 'feed', confidence: 0.9 })
    // out-of-range confidence is dropped but the indicator is kept
    expect(clean[1]).toEqual({ value: 'd.example', type: 'domain', category: 'phishing' })
  })

  it('returns an empty array for non-array input', () => {
    expect(sanitizeIndicators(null)).toEqual([])
    expect(sanitizeIndicators({ indicators: [] })).toEqual([])
  })
})

describe('network-guard · hasBlockingEvent', () => {
  it('is true when any event blocks', () => {
    const events = [
      evaluateDestination({ destination: 'good.example' }, index, now),
      evaluateDestination({ destination: 'evil-c2.example' }, index, now),
    ]
    expect(hasBlockingEvent(events)).toBe(true)
  })

  it('is false when all events allow/alert', () => {
    const events = [
      evaluateDestination({ destination: 'good.example' }, index, now),
      evaluateDestination({ destination: 'proxy.example' }, index, now),
    ]
    expect(hasBlockingEvent(events)).toBe(false)
  })
})
