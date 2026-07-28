/**
 * Calm, deterministic copy for emergency device isolation.
 * Does not invent network behavior — describes the intended isolate policy.
 */

export type IsolationExplanation = {
  why: string[]
  stillWorks: string[]
  blocked: string[]
  recommended: string
}

/** Explain what emergency isolation does for a parent. */
export function explainIsolation(deviceName?: string): IsolationExplanation {
  const name = (deviceName || 'This device').trim() || 'This device'
  return {
    why: [
      `${name} will use a strict allowlist DNS mode so most internet destinations stop resolving.`,
      'Use this when you suspect malware, a compromised streaming box, or unexpected remote access.',
      'Isolation is reversible — you can clear it from the same parent controls.',
    ],
    stillWorks: [
      'Bulwrk heartbeats and parent commands continue (so you can clear isolation remotely).',
      'Local apps that do not need the internet keep running.',
      'You can still request scans and view findings from the parent panel.',
    ],
    blocked: [
      'Most websites, apps, and streaming services that need the internet.',
      'New downloads and updates that rely on blocked DNS names.',
      'On Android TV, VPN/DNS Guard permission may be required before isolate fully applies.',
    ],
    recommended: 'Confirm the device name, isolate now, then watch heartbeats and network events. Clear isolation when the risk has passed.',
  }
}

export function explainClearIsolation(deviceName?: string): IsolationExplanation {
  const name = (deviceName || 'This device').trim() || 'This device'
  return {
    why: [
      `Clearing isolation restores normal DNS policy for ${name}.`,
      'Only clear when you believe the threat is handled or you need full internet access again.',
    ],
    stillWorks: [
      'Parent controls, scans, and findings stay available.',
      'Any blocked-domain policy you saved separately still applies.',
    ],
    blocked: [
      'Emergency allowlist isolation will no longer be enforced.',
    ],
    recommended: 'Clear isolation, then run a quick malware or health scan to confirm the device looks safe.',
  }
}
