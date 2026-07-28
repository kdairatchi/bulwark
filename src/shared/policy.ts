// User-defined network rules — global or per-application allow/block policy that
// augments the automatic Network Guard verdict (Portmaster-style "create your
// own rules" + "global & per-app settings").

import type { NetworkDecision, ThreatCategory } from './network-guard'

export type RuleAction = 'allow' | 'block'

/** Scope: everything, or a single application (matched by process name). */
export type RuleScope = { kind: 'global' } | { kind: 'app'; app: string }

/** A rule matches when every provided criterion matches (AND). */
export interface RuleMatch {
  /** Domain or parent domain (suffix match). */
  domain?: string
  /** Exact remote IP. */
  ip?: string
  /** Remote port. */
  port?: number
  /** Threat category from the indicator engine. */
  category?: ThreatCategory
}

export interface NetworkRule {
  id: string
  name?: string
  scope: RuleScope
  match: RuleMatch
  action: RuleAction
  enabled: boolean
}

/** Context a rule is evaluated against. */
export interface RuleContext {
  domain?: string
  ip?: string
  port?: number
  category?: ThreatCategory
  app?: string
}

export interface PolicyResult {
  action: RuleAction
  rule: NetworkRule
}

/** Map a rule action to the guard decision it forces. */
export function actionToDecision(action: RuleAction): NetworkDecision {
  return action === 'block' ? 'block' : 'allow'
}
