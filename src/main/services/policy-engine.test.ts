import { describe, it, expect } from 'vitest'
import { evaluateRules, applyPolicy } from './policy-engine'
import type { NetworkRule } from '../../shared/policy'
import type { NetworkEvent } from '../../shared/network-guard'

function rule(partial: Partial<NetworkRule>): NetworkRule {
  return {
    id: partial.id ?? 'r1',
    name: partial.name,
    scope: partial.scope ?? { kind: 'global' },
    match: partial.match ?? {},
    action: partial.action ?? 'block',
    enabled: partial.enabled ?? true,
  }
}

const allowEvent: NetworkEvent = {
  destination: 'cdn.example.com',
  destinationType: 'domain',
  decision: 'allow',
  reason: 'no_match',
  confidence: 0,
  timestamp: '2026-07-28T00:00:00.000Z',
}

describe('policy-engine · evaluateRules', () => {
  it('matches a global domain block (incl. subdomains)', () => {
    const rules = [rule({ id: 'b', match: { domain: 'example.com' }, action: 'block' })]
    expect(evaluateRules({ domain: 'cdn.example.com' }, rules)?.action).toBe('block')
    expect(evaluateRules({ domain: 'other.net' }, rules)).toBeNull()
  })

  it('ignores disabled rules', () => {
    const rules = [rule({ match: { domain: 'example.com' }, enabled: false })]
    expect(evaluateRules({ domain: 'example.com' }, rules)).toBeNull()
  })

  it('does not let a criteria-less global rule match everything', () => {
    const rules = [rule({ match: {}, scope: { kind: 'global' }, action: 'block' })]
    expect(evaluateRules({ domain: 'anything.example' }, rules)).toBeNull()
  })

  it('matches a per-app rule only for that app', () => {
    const rules = [rule({ scope: { kind: 'app', app: 'firefox' }, match: { port: 443 }, action: 'block' })]
    expect(evaluateRules({ app: 'firefox', port: 443 }, rules)?.action).toBe('block')
    expect(evaluateRules({ app: 'curl', port: 443 }, rules)).toBeNull()
  })

  it('prefers app scope over global', () => {
    const rules = [
      rule({ id: 'g', scope: { kind: 'global' }, match: { domain: 'example.com' }, action: 'block' }),
      rule({ id: 'a', scope: { kind: 'app', app: 'firefox' }, match: { domain: 'example.com' }, action: 'allow' }),
    ]
    const res = evaluateRules({ app: 'firefox', domain: 'example.com' }, rules)
    expect(res?.rule.id).toBe('a')
    expect(res?.action).toBe('allow')
  })

  it('prefers block over allow within the same scope', () => {
    const rules = [
      rule({ id: 'allow', match: { domain: 'example.com' }, action: 'allow' }),
      rule({ id: 'block', match: { domain: 'example.com' }, action: 'block' }),
    ]
    expect(evaluateRules({ domain: 'example.com' }, rules)?.rule.id).toBe('block')
  })

  it('matches by category and by port', () => {
    const catRule = [rule({ match: { category: 'c2' }, action: 'block' })]
    expect(evaluateRules({ category: 'c2' }, catRule)?.action).toBe('block')
    const portRule = [rule({ scope: { kind: 'app', app: 'x' }, match: { port: 23 }, action: 'block' })]
    expect(evaluateRules({ app: 'x', port: 23 }, portRule)?.action).toBe('block')
    expect(evaluateRules({ app: 'x', port: 24 }, portRule)).toBeNull()
  })
})

describe('policy-engine · applyPolicy', () => {
  it('forces a block and rewrites the reason', () => {
    const rules = [rule({ id: 'r', name: 'block-ads', match: { domain: 'example.com' }, action: 'block' })]
    const out = applyPolicy(allowEvent, { domain: 'cdn.example.com' }, rules)
    expect(out.decision).toBe('block')
    expect(out.reason).toBe('rule:block-ads')
    expect(out.confidence).toBe(1)
  })

  it('lets an allow rule whitelist an otherwise-blocked destination', () => {
    const blockedEvent: NetworkEvent = { ...allowEvent, decision: 'block', reason: 'known_c2', category: 'c2', confidence: 0.97 }
    const rules = [rule({ id: 'w', name: 'trust', match: { domain: 'cdn.example.com' }, action: 'allow' })]
    const out = applyPolicy(blockedEvent, { domain: 'cdn.example.com' }, rules)
    expect(out.decision).toBe('allow')
    expect(out.category).toBeUndefined()
  })

  it('returns the event unchanged when no rule matches', () => {
    expect(applyPolicy(allowEvent, { domain: 'nomatch.example' }, [])).toBe(allowEvent)
  })
})
