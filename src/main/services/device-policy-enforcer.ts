/**
 * Applies remote device policy to the local DoT DNS resolver.
 *
 * Isolation uses allowlist mode on the loopback resolver only — it does NOT
 * rewrite /etc/resolv.conf (that remains a user-driven Network Guard action).
 */

import { dnsResolver } from './dns-resolver'
import { cloudLog } from './logger'

export interface RemoteDevicePolicy {
  version: number
  updatedAt: string
  isolated: boolean
  dnsGuardRequired: boolean
  blockedDomains: string[]
  isolationAllowlist: string[]
  allowInstallUnknown: boolean
}

export interface AgentNetworkEvent {
  type: string
  at?: string
  subject?: string | null
  detail?: string | null
  metadata?: Record<string, unknown>
}

const DEFAULT_ALLOWLIST = [
  'googleapis.com',
  'gvt1.com',
  'android.com',
  'google.com',
  'cloudflare.com',
  '1.1.1.1',
]

function normalizeDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/\.$/, '')
  if (!d || d.length > 253) return null
  if (!d.includes('.')) return null
  if (!/^[a-z0-9._-]+$/.test(d)) return null
  return d
}

export function parseRemotePolicy(input: unknown): RemoteDevicePolicy {
  const o = (input ?? {}) as Record<string, unknown>
  const blocked = Array.isArray(o.blockedDomains)
    ? o.blockedDomains.filter((d): d is string => typeof d === 'string').map((d) => normalizeDomain(d)).filter((d): d is string => !!d)
    : []
  const allow = Array.isArray(o.isolationAllowlist)
    ? o.isolationAllowlist.filter((d): d is string => typeof d === 'string').map((d) => normalizeDomain(d)).filter((d): d is string => !!d)
    : []
  return {
    version: typeof o.version === 'number' ? o.version : 1,
    updatedAt: typeof o.updatedAt === 'string' ? o.updatedAt : new Date().toISOString(),
    isolated: o.isolated === true,
    dnsGuardRequired: o.dnsGuardRequired === true,
    blockedDomains: blocked,
    isolationAllowlist: allow.length > 0 ? allow : [...DEFAULT_ALLOWLIST],
    allowInstallUnknown: o.allowInstallUnknown === true,
  }
}

export class DevicePolicyEnforcer {
  private policy: RemoteDevicePolicy | null = null
  private manualBlocks = new Set<string>()
  private pendingEvents: AgentNetworkEvent[] = []
  private localBlocklistProvider: () => string[] = () => []
  private hookInstalled = false
  private resolverStartConfig: { port?: number } | undefined

  /** Provide local Network Guard domains (starter + filter lists + rules). */
  setLocalBlocklistProvider(fn: () => string[]): void {
    this.localBlocklistProvider = fn
  }

  /** Prefer ephemeral ports in tests (`{ port: 0 }`) to avoid clashing with :5353. */
  setResolverStartConfig(config?: { port?: number }): void {
    this.resolverStartConfig = config
  }

  getPolicy(): RemoteDevicePolicy | null {
    return this.policy
  }

  isIsolated(): boolean {
    return this.policy?.isolated === true
  }

  /** Domains from remote policy + BLOCK_DOMAIN commands (blocklist mode). */
  remoteBlockedDomains(): string[] {
    return [
      ...(this.policy?.blockedDomains ?? []),
      ...this.manualBlocks,
    ]
  }

  /** Clear BLOCK_DOMAIN / threat-feed manual blocks (does not clear filter lists). */
  clearManualBlocks(): void {
    this.manualBlocks.clear()
  }

  pushEvent(type: string, subject?: string | null, detail?: string | null): void {
    this.pendingEvents.push({
      type,
      at: new Date().toISOString(),
      subject: subject ?? null,
      detail: detail ?? null,
      metadata: {},
    })
    if (this.pendingEvents.length > 500) {
      this.pendingEvents.splice(0, this.pendingEvents.length - 500)
    }
  }

  drainEvents(): AgentNetworkEvent[] {
    const out = this.pendingEvents
    this.pendingEvents = []
    return out
  }

  /** Clear remote policy / blocks / events (tests only). */
  resetForTest(): void {
    this.policy = null
    this.manualBlocks.clear()
    this.pendingEvents = []
    this.hookInstalled = false
    this.resolverStartConfig = undefined
    this.localBlocklistProvider = () => []
  }

  private ensureBlockHook(): void {
    if (this.hookInstalled) return
    dnsResolver.setOnBlocked((name, via) => {
      this.pushEvent('dns_blocked', name, via)
    })
    this.hookInstalled = true
  }

  /**
   * Rebuild resolver filter from current remote policy + local lists.
   * Starts the loopback DoT resolver when isolation or dnsGuardRequired is set.
   * Never touches system DNS (resolv.conf / netsh / networksetup).
   */
  async reapply(startConfig?: { port?: number }): Promise<{
    mode: 'blocklist' | 'allowlist'
    domainCount: number
    resolverRunning: boolean
    address: string | null
  }> {
    this.ensureBlockHook()
    const ensureStarted = async () => {
      if (!dnsResolver.getStats().running) {
        await dnsResolver.start(startConfig ?? this.resolverStartConfig)
        cloudLog('INFO', 'device-policy: started loopback resolver', {
          address: dnsResolver.getStats().address,
        })
      }
    }

    if (this.policy?.isolated) {
      const allow = this.policy.isolationAllowlist
      dnsResolver.setFilterMode('allowlist', allow)
      await ensureStarted()
      const stats = dnsResolver.getStats()
      return {
        mode: 'allowlist',
        domainCount: allow.length,
        resolverRunning: stats.running,
        address: stats.address,
      }
    }

    const domains = [
      ...this.localBlocklistProvider(),
      ...this.remoteBlockedDomains(),
    ]
    dnsResolver.setFilterMode('blocklist', domains)
    if (this.policy?.dnsGuardRequired || this.manualBlocks.size > 0 || (this.policy?.blockedDomains.length ?? 0) > 0) {
      await ensureStarted()
    }
    const stats = dnsResolver.getStats()
    return {
      mode: 'blocklist',
      domainCount: domains.length,
      resolverRunning: stats.running,
      address: stats.address,
    }
  }

  async applyRemotePolicy(
    policy: RemoteDevicePolicy,
    startConfig?: { port?: number },
  ): Promise<Record<string, unknown>> {
    const prevIsolated = this.policy?.isolated === true
    this.policy = policy
    const applied = await this.reapply(startConfig)
    if (policy.isolated && !prevIsolated) {
      this.pushEvent('isolation_enabled', 'device', 'policy')
    } else if (!policy.isolated && prevIsolated) {
      this.pushEvent('isolation_cleared', 'device', 'policy')
    }
    return {
      ok: true,
      stub: false,
      applied: true,
      isolated: policy.isolated,
      dnsGuardRequired: policy.dnsGuardRequired,
      version: policy.version,
      ...applied,
      systemDnsUnchanged: true,
    }
  }

  async blockDomain(domain: string): Promise<Record<string, unknown>> {
    const n = normalizeDomain(domain)
    if (!n) return { ok: false, stub: false, applied: false, error: 'invalid domain' }
    this.manualBlocks.add(n)
    if (this.policy) {
      const set = new Set(this.policy.blockedDomains)
      set.add(n)
      this.policy = { ...this.policy, blockedDomains: [...set] }
    }
    const applied = await this.reapply()
    this.pushEvent('dns_policy_block_added', n, 'BLOCK_DOMAIN')
    return { ok: true, stub: false, applied: true, domain: n, ...applied, systemDnsUnchanged: true }
  }
}

export const devicePolicyEnforcer = new DevicePolicyEnforcer()
