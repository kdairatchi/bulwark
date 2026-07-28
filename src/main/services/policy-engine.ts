// Pure evaluation of user-defined network rules. No I/O — persistence and
// wiring live elsewhere. Precedence, from strongest to weakest:
//   1. app-scoped over global
//   2. block over allow (deny wins within the same scope)
//   3. more specific match (more criteria) over less specific
// This keeps an explicit per-app block from being silently overridden by a
// broad global allow.

import type { NetworkEvent } from '../../shared/network-guard'
import type { NetworkRule, PolicyResult, RuleContext } from '../../shared/policy'
import { actionToDecision } from '../../shared/policy'

function domainMatches(ruleDomain: string, ctxDomain: string): boolean {
  const r = ruleDomain.toLowerCase().replace(/\.$/, '')
  const c = ctxDomain.toLowerCase().replace(/\.$/, '')
  return c === r || c.endsWith(`.${r}`)
}

function ruleMatches(rule: NetworkRule, ctx: RuleContext): boolean {
  if (!rule.enabled) return false
  if (rule.scope.kind === 'app') {
    if (!ctx.app || ctx.app.toLowerCase() !== rule.scope.app.toLowerCase()) return false
  }
  const m = rule.match
  if (m.domain) {
    if (!ctx.domain || !domainMatches(m.domain, ctx.domain)) return false
  }
  if (m.ip) {
    if (!ctx.ip || ctx.ip !== m.ip) return false
  }
  if (typeof m.port === 'number') {
    if (ctx.port !== m.port) return false
  }
  if (m.category) {
    if (ctx.category !== m.category) return false
  }
  // A rule with no criteria and global scope would match everything; require at
  // least one criterion OR an app scope to avoid an accidental match-all.
  const hasCriteria = !!(m.domain || m.ip || typeof m.port === 'number' || m.category)
  if (!hasCriteria && rule.scope.kind === 'global') return false
  return true
}

function specificity(rule: NetworkRule): number {
  const m = rule.match
  return (m.domain ? 1 : 0) + (m.ip ? 1 : 0) + (typeof m.port === 'number' ? 1 : 0) + (m.category ? 1 : 0)
}

/** Return the decisive rule for a context, or null if none apply. */
export function evaluateRules(ctx: RuleContext, rules: NetworkRule[]): PolicyResult | null {
  const matches = rules.filter((r) => ruleMatches(r, ctx))
  if (matches.length === 0) return null

  matches.sort((a, b) => {
    // app scope first
    const scopeA = a.scope.kind === 'app' ? 1 : 0
    const scopeB = b.scope.kind === 'app' ? 1 : 0
    if (scopeA !== scopeB) return scopeB - scopeA
    // block before allow
    const blockA = a.action === 'block' ? 1 : 0
    const blockB = b.action === 'block' ? 1 : 0
    if (blockA !== blockB) return blockB - blockA
    // more specific first
    return specificity(b) - specificity(a)
  })

  const rule = matches[0]
  return { action: rule.action, rule }
}

/**
 * Apply user rules on top of an automatic NetworkEvent. A matching rule wins:
 * block forces a block; allow forces an allow (an explicit user whitelist that
 * overrides an indicator match).
 */
export function applyPolicy(event: NetworkEvent, ctx: RuleContext, rules: NetworkRule[]): NetworkEvent {
  const result = evaluateRules(ctx, rules)
  if (!result) return event
  const decision = actionToDecision(result.action)
  return {
    ...event,
    decision,
    reason: `rule:${result.rule.name || result.rule.id}`,
    confidence: 1,
    category: decision === 'allow' ? undefined : event.category,
  }
}
