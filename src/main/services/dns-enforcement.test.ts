import { describe, it, expect } from 'vitest'
import { buildEnforcementPlan, buildResolvConf, isBulwrkManagedResolvConf } from './dns-enforcement'

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
    expect(plan.revert.some((s) => /resolv\.conf/.test(s.command))).toBe(true)
  })

  it('uses networksetup on macOS', () => {
    const plan = buildEnforcementPlan('darwin', 5353)
    expect(plan.method).toBe('networksetup')
    expect(plan.apply[0].command).toMatch(/networksetup/)
    expect(plan.revert[0].command).toMatch(/networksetup/)
  })

  it('uses netsh on Windows', () => {
    const plan = buildEnforcementPlan('win32', 5353)
    expect(plan.method).toBe('netsh')
    expect(plan.apply[0].command).toMatch(/netsh/)
    expect(plan.revert[0].command).toMatch(/dhcp/)
  })

  it('always marks enforcement as requiring elevation', () => {
    for (const p of ['linux', 'darwin', 'win32'] as NodeJS.Platform[]) {
      expect(buildEnforcementPlan(p, 5353).requiresElevation).toBe(true)
    }
  })
})
