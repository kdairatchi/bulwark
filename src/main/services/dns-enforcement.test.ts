import { describe, it, expect } from 'vitest'
import { buildEnforcementPlan, buildResolvConf, isBulwrkManagedResolvConf, parseMacDnsServices, parseWindowsDnsEntries } from './dns-enforcement'

describe('dns-enforcement · buildResolvConf', () => {
  it('produces a resolv.conf pointing at the given nameserver', () => {
    const out = buildResolvConf('127.0.0.1')
    expect(out).toMatch(/nameserver 127\.0\.0\.1/)
    expect(out).toMatch(/Bulwrk/)
  })

  it('detects our own (potentially stale) resolv.conf via its marker', () => {
    expect(isBulwrkManagedResolvConf(buildResolvConf('127.0.0.1'))).toBe(true)
    expect(isBulwrkManagedResolvConf('nameserver 10.0.0.2\n')).toBe(false)
  })
})

describe('dns-enforcement · buildEnforcementPlan', () => {
  it('uses the resolv.conf method on Linux with apply + revert steps', () => {
    const plan = buildEnforcementPlan('linux', 5353)
    expect(plan.method).toBe('resolv.conf')
    expect(plan.requiresElevation).toBe(true)
    expect(plan.apply.length).toBeGreaterThanOrEqual(3)
    expect(plan.revert.length).toBeGreaterThanOrEqual(2)
    // The plan references the helper on :53 forwarding to the resolver port.
    expect(plan.apply.some((s) => s.command.includes('5353'))).toBe(true)
    expect(plan.apply.some((s) => s.command.includes('pkexec'))).toBe(true)
    expect(plan.revert.some((s) => /resolv\.conf/.test(s.command))).toBe(true)
  })

  it('uses networksetup on macOS', () => {
    const plan = buildEnforcementPlan('darwin', 5353)
    expect(plan.method).toBe('networksetup')
    expect(plan.apply.some((step) => /networksetup/.test(step.command))).toBe(true)
    expect(plan.revert.some((step) => /networksetup/.test(step.command))).toBe(true)
  })

  it('uses netsh on Windows', () => {
    const plan = buildEnforcementPlan('win32', 5353)
    expect(plan.method).toBe('netsh')
    expect(plan.apply.some((step) => /Set-DnsClientServerAddress/.test(step.command))).toBe(true)
    expect(plan.revert.some((step) => /saved servers/.test(step.command))).toBe(true)
  })

  it('always marks enforcement as requiring elevation', () => {
    for (const p of ['linux', 'darwin', 'win32'] as NodeJS.Platform[]) {
      expect(buildEnforcementPlan(p, 5353).requiresElevation).toBe(true)
    }
  })
})

describe('dns-enforcement · platform state parsing', () => {
  it('keeps Windows IPv4 and IPv6 settings while discarding malformed rows', () => {
    const entries = parseWindowsDnsEntries(JSON.stringify([
      { InterfaceIndex: 7, InterfaceAlias: 'Wi-Fi', AddressFamily: 2, ServerAddresses: ['192.0.2.1'] },
      { InterfaceIndex: 7, InterfaceAlias: 'Wi-Fi', AddressFamily: 23, ServerAddresses: ['2001:db8::53'] },
      { InterfaceIndex: 'bad', AddressFamily: 2, ServerAddresses: ['127.0.0.1'] },
    ]))
    expect(entries).toHaveLength(2)
    expect(entries[1].AddressFamily).toBe(23)
  })

  it('preserves macOS services with DHCP-managed empty DNS lists', () => {
    expect(parseMacDnsServices('Wi-Fi\n*Thunderbolt\nEthernet\n', { 'Wi-Fi': 'There aren\'t any DNS Servers set on Wi-Fi.', Ethernet: '1.1.1.1\n' })).toEqual([
      { service: 'Wi-Fi', servers: [] },
      { service: 'Ethernet', servers: ['1.1.1.1'] },
    ])
  })
})
