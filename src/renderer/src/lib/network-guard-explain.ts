/**
 * Calm, deterministic copy for Network Guard first-enable (Secure DNS).
 * Describes intended local resolver + optional system-wide enforcement —
 * does not invent OS APIs or claim packet inspection.
 */

export type NetworkGuardEnableExplanation = {
  why: string[]
  whatHappens: string[]
  stillWorks: string[]
  enforcementNotes: string[]
  recommended: string
}

/** Explain turning on the local Secure DNS resolver. */
export function explainSecureDnsEnable(): NetworkGuardEnableExplanation {
  return {
    why: [
      'Secure DNS runs a local filtering resolver on this device so lookups can be encrypted and checked against filter lists.',
      'Bulwrk looks at DNS names and connection metadata — not the contents of your browsing or app traffic.',
      'Starting the resolver alone does not change system-wide DNS until you opt into Protect this device.',
    ],
    whatHappens: [
      'A local DNS-over-TLS resolver starts and listens on a loopback address you can point apps or the OS at.',
      'Enabled filter lists block known tracker/malware domains; your custom Network Guard rules also feed the filter.',
      'Recent queries appear in Network Guard so you can see what was blocked or forwarded.',
    ],
    stillWorks: [
      'Apps keep working for allowed destinations — only listed bad domains are blocked by default.',
      'You can stop the resolver anytime from the same Secure DNS tab.',
      'Connections, rules, port scan, and destination check tabs stay available either way.',
    ],
    enforcementNotes: [
      'Protect this device routes ALL system DNS through Bulwrk. That needs elevation and backs up your previous DNS settings.',
      'Enforcement auto-reverts as a safety backstop if something goes wrong.',
      'You can enable enforcement after the resolver is running — it is optional for first start.',
    ],
    recommended:
      'Start the local resolver first, update filter lists, then enable Protect this device only if you want system-wide coverage.',
  }
}

export type NetworkGuardEnforceExplanation = {
  why: string[]
  whatHappens: string[]
  stillWorks: string[]
  risks: string[]
  recommended: string
}

/** Explain enabling system-wide DNS enforcement (Protect this device). */
export function explainSecureDnsEnforce(resolverAddress?: string): NetworkGuardEnforceExplanation {
  const address = (resolverAddress || 'the local Bulwrk resolver').trim() || 'the local Bulwrk resolver'
  return {
    why: [
      'Protect this device routes every app’s DNS lookups through Bulwrk’s filtering resolver — not just apps you configure by hand.',
      'Lookups stay encrypted to the upstream resolver where supported, and filter lists / Network Guard rules apply system-wide.',
      'Bulwrk still uses DNS names and connection metadata — not the contents of your traffic.',
    ],
    whatHappens: [
      `System DNS is pointed at ${address}. Elevation may be required.`,
      'Your previous DNS settings are backed up so Disable can restore them.',
      'A safety backstop auto-reverts enforcement if something goes wrong.',
    ],
    stillWorks: [
      'Allowed destinations keep resolving; listed tracker/malware domains stay blocked.',
      'You can Disable anytime from the same Secure DNS tab to restore the backup.',
      'The local resolver must stay running while enforcement is active.',
    ],
    risks: [
      'If the resolver stops while enforcement is on, some apps may fail DNS until Disable or auto-revert runs.',
      'Corporate or VPN DNS policies may conflict — Disable if you need the network’s DNS again.',
    ],
    recommended:
      'Confirm the resolver is healthy, enable Protect this device, then verify a few sites load. Disable immediately if anything looks wrong.',
  }
}
