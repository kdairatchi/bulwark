/**
 * Shared local DNS blocklist rebuild for Network Guard IPC + remote threat-feed sync.
 */

import { dnsResolver } from './dns-resolver'
import { STARTER_BLOCKLIST } from './dns-filter'
import { loadRules } from './network-rules-store'
import { mergedBlocklistDomains } from './filter-lists'
import { getEnabledListIds } from './filter-lists-store'
import { devicePolicyEnforcer } from './device-policy-enforcer'
import type { NetworkRule } from '../../shared/policy'

export function buildLocalResolverBlocklist(rules: NetworkRule[] = loadRules()): string[] {
  const domains = [...STARTER_BLOCKLIST, ...mergedBlocklistDomains(getEnabledListIds())]
  for (const r of rules) {
    if (r.enabled && r.action === 'block' && r.match.domain) domains.push(r.match.domain)
  }
  return domains
}

/**
 * Wire local lists into the policy enforcer and refresh the loopback resolver
 * (unless isolation allowlist mode is active).
 */
export function refreshResolverBlocklist(): void {
  devicePolicyEnforcer.setLocalBlocklistProvider(() => buildLocalResolverBlocklist(loadRules()))
  if (devicePolicyEnforcer.isIsolated()) {
    void devicePolicyEnforcer.reapply()
    return
  }
  const domains = [
    ...buildLocalResolverBlocklist(loadRules()),
    ...devicePolicyEnforcer.remoteBlockedDomains(),
  ]
  dnsResolver.setFilterMode('blocklist', domains)
}
