import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { EventEmitter } from 'events'
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  buildEnforcementPlan,
  buildResolvConf,
  isBulwarkManagedResolvConf,
  parseNetworkServices,
  selectDarwinDnsTargets,
  parseNetshInterfaces,
  selectWinDnsTargets,
  parseDarwinDnsServers,
  parseWinDnsServers,
  DnsEnforcement,
} from './dns-enforcement'

describe('dns-enforcement · buildResolvConf', () => {
  it('produces a resolv.conf pointing at the given nameserver', () => {
    const out = buildResolvConf('127.0.0.1')
    expect(out).toMatch(/nameserver 127\.0\.0\.1/)
    expect(out).toMatch(/Bulwark/)
  })

  it('detects our own (potentially stale) resolv.conf via its marker', () => {
    expect(isBulwarkManagedResolvConf(buildResolvConf('127.0.0.1'))).toBe(true)
    expect(isBulwarkManagedResolvConf('nameserver 10.0.0.2\n')).toBe(false)
  })
})

describe('dns-enforcement · parsers', () => {
  it('parses networksetup service lists and skips disabled entries', () => {
    const stdout = `An asterisk (*) denotes that a network service is disabled.
Wi-Fi
Ethernet
* iPhone USB
Thunderbolt Bridge
`
    expect(parseNetworkServices(stdout)).toEqual(['Wi-Fi', 'Ethernet', 'Thunderbolt Bridge'])
    expect(selectDarwinDnsTargets(parseNetworkServices(stdout))).toEqual(['Wi-Fi', 'Ethernet'])
  })

  it('parses netsh interface tables', () => {
    const stdout = `
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
  1          75  4294967295  connected     Loopback Pseudo-Interface 1
 12          25        1500  connected     Wi-Fi
 15          25        1500  disconnected  Ethernet
`
    const ifaces = parseNetshInterfaces(stdout)
    expect(selectWinDnsTargets(ifaces)).toEqual(['Wi-Fi'])
  })

  it('parses darwin DNS server output', () => {
    expect(parseDarwinDnsServers("There aren't any DNS Servers set on Wi-Fi.")).toBe('dhcp')
    expect(parseDarwinDnsServers('1.1.1.1\n8.8.8.8\n')).toEqual(['1.1.1.1', '8.8.8.8'])
  })

  it('parses windows DNS show output', () => {
    expect(parseWinDnsServers('Configuration for interface "Wi-Fi"\nDNS servers configured through DHCP')).toEqual({
      mode: 'dhcp',
      servers: [],
    })
    expect(parseWinDnsServers('Statically Configured DNS Servers: 1.1.1.1\n                            8.8.8.8')).toEqual({
      mode: 'static',
      servers: ['1.1.1.1', '8.8.8.8'],
    })
  })
})

describe('dns-enforcement · buildEnforcementPlan', () => {
  it('uses the resolv.conf method on Linux with apply + revert steps', () => {
    const plan = buildEnforcementPlan('linux', 5353)
    expect(plan.method).toBe('resolv.conf')
    expect(plan.requiresElevation).toBe(true)
    expect(plan.apply.length).toBeGreaterThanOrEqual(3)
    expect(plan.revert.length).toBeGreaterThanOrEqual(2)
    expect(plan.apply.some((s) => s.command.includes('5353'))).toBe(true)
    expect(plan.revert.some((s) => /resolv\.conf/.test(s.command))).toBe(true)
  })

  it('uses networksetup on macOS and includes the :53 helper', () => {
    const plan = buildEnforcementPlan('darwin', 5353, ['Wi-Fi'])
    expect(plan.method).toBe('networksetup')
    expect(plan.apply.some((s) => s.command.includes('5353'))).toBe(true)
    expect(plan.apply.some((s) => s.command.includes('networksetup') && s.command.includes('Wi-Fi'))).toBe(true)
    expect(plan.revert.some((s) => /Empty|networksetup/.test(s.command))).toBe(true)
  })

  it('uses netsh on Windows and includes the :53 helper', () => {
    const plan = buildEnforcementPlan('win32', 5353, ['Wi-Fi'])
    expect(plan.method).toBe('netsh')
    expect(plan.apply.some((s) => s.command.includes('5353'))).toBe(true)
    expect(plan.apply.some((s) => /netsh.*Wi-Fi.*127\.0\.0\.1/.test(s.command))).toBe(true)
    expect(plan.revert.some((s) => /dhcp/.test(s.command))).toBe(true)
  })

  it('always marks enforcement as requiring elevation', () => {
    for (const p of ['linux', 'darwin', 'win32'] as NodeJS.Platform[]) {
      expect(buildEnforcementPlan(p, 5353).requiresElevation).toBe(true)
    }
  })
})

function mockHelperProcess(): EventEmitter & { stdout: EventEmitter; pid: number; kill: () => void } {
  const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; pid: number; kill: () => void }
  child.stdout = new EventEmitter()
  child.pid = 4242
  child.kill = vi.fn()
  queueMicrotask(() => child.stdout.emit('data', Buffer.from('helper-udp-ready\n')))
  return child
}

describe('dns-enforcement · apply/revert (mocked darwin/win32)', () => {
  let dir: string
  let execCalls: Array<{ file: string; args: string[] }>

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bulwark-dns-enf-'))
    mkdirSync(join(dir, 'enforcement'), { recursive: true })
    execCalls = []
  })

  afterEach(() => {
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true })
  })

  it('applies and reverts darwin DNS via networksetup', async () => {
    const enf = new DnsEnforcement({
      isResolverRunning: () => true,
      resolverPort: () => 5353,
      audit: vi.fn(),
      platform: () => 'darwin',
      dataDir: () => join(dir, 'enforcement'),
      spawnElevated: () => mockHelperProcess() as any,
      exec: async (file, args) => {
        execCalls.push({ file, args })
        if (file === 'networksetup' && args[0] === '-listallnetworkservices') {
          return { stdout: 'An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n', stderr: '' }
        }
        if (file === 'networksetup' && args[0] === '-getdnsservers') {
          return { stdout: "There aren't any DNS Servers set on Wi-Fi.\n", stderr: '' }
        }
        return { stdout: '', stderr: '' }
      },
    })

    const status = await enf.apply()
    expect(status.enforcing).toBe(true)
    expect(status.method).toBe('networksetup')
    expect(status.targets).toEqual(['Wi-Fi'])
    expect(execCalls.some((c) =>
      c.file === 'sudo' && c.args.includes('networksetup') && c.args.includes('-setdnsservers') && c.args.includes('127.0.0.1'),
    )).toBe(true)
    expect(existsSync(join(dir, 'enforcement', 'dns-backup.json'))).toBe(true)

    const reverted = await enf.revert('test')
    expect(reverted.enforcing).toBe(false)
    expect(execCalls.some((c) =>
      c.file === 'sudo' && c.args.includes('networksetup') && c.args.includes('-setdnsservers') && c.args.includes('Empty'),
    )).toBe(true)
    expect(existsSync(join(dir, 'enforcement', 'dns-backup.json'))).toBe(false)
  })

  it('applies and reverts win32 DNS via netsh (DHCP restore)', async () => {
    const enf = new DnsEnforcement({
      isResolverRunning: () => true,
      resolverPort: () => 5353,
      audit: vi.fn(),
      platform: () => 'win32',
      dataDir: () => join(dir, 'enforcement'),
      spawnElevated: () => mockHelperProcess() as any,
      exec: async (file, args) => {
        execCalls.push({ file, args })
        if (file === 'netsh' && args.includes('show') && args.includes('interfaces')) {
          return {
            stdout: 'Idx Met MTU State Name\n--- --- --- ----- ----\n 12 25 1500 connected Ethernet\n',
            stderr: '',
          }
        }
        if (file === 'netsh' && args.includes('show') && args.includes('dns')) {
          return { stdout: 'DNS servers configured through DHCP\n', stderr: '' }
        }
        return { stdout: '', stderr: '' }
      },
    })

    const status = await enf.apply()
    expect(status.enforcing).toBe(true)
    expect(status.method).toBe('netsh')
    expect(status.targets).toEqual(['Ethernet'])
    expect(execCalls.some((c) => c.args.includes('static') && c.args.includes('127.0.0.1'))).toBe(true)

    await enf.revert('test')
    expect(execCalls.some((c) => c.args.includes('dhcp'))).toBe(true)
  })

  it('refuses to apply when the resolver is not running', async () => {
    const enf = new DnsEnforcement({
      isResolverRunning: () => false,
      resolverPort: () => 5353,
      audit: vi.fn(),
      platform: () => 'darwin',
      dataDir: () => join(dir, 'enforcement'),
      exec: async () => ({ stdout: '', stderr: '' }),
    })
    const status = await enf.apply()
    expect(status.enforcing).toBe(false)
    expect(status.message).toMatch(/Secure DNS resolver/i)
  })

  it('restores static DNS servers on darwin revert', async () => {
    writeFileSync(join(dir, 'enforcement', 'dns-backup.json'), JSON.stringify({
      platform: 'darwin',
      method: 'networksetup',
      createdAt: new Date().toISOString(),
      targets: [{ name: 'Wi-Fi', mode: 'static', servers: ['1.1.1.1', '8.8.8.8'] }],
    }))
    writeFileSync(join(dir, 'enforcement', 'enforcing.lock'), 'x')

    const enf = new DnsEnforcement({
      isResolverRunning: () => true,
      resolverPort: () => 5353,
      audit: vi.fn(),
      platform: () => 'darwin',
      dataDir: () => join(dir, 'enforcement'),
      spawnElevated: () => mockHelperProcess() as any,
      exec: async (file, args) => {
        execCalls.push({ file, args })
        return { stdout: '', stderr: '' }
      },
    })
    // Force internal enforcing flag via apply path skipped — call revert after priming state
    // by reading backup through reconcile
    await enf.reconcileOnStartup()
    expect(execCalls.some((c) =>
      c.file === 'sudo'
      && c.args.includes('networksetup')
      && c.args.includes('-setdnsservers')
      && c.args.includes('Wi-Fi')
      && c.args.includes('1.1.1.1')
      && c.args.includes('8.8.8.8'),
    )).toBe(true)
    expect(existsSync(join(dir, 'enforcement', 'dns-backup.json'))).toBe(false)
  })

  it('writes a backup file with expected shape on win32 apply', async () => {
    const enf = new DnsEnforcement({
      isResolverRunning: () => true,
      resolverPort: () => 5353,
      audit: vi.fn(),
      platform: () => 'win32',
      dataDir: () => join(dir, 'enforcement'),
      spawnElevated: () => mockHelperProcess() as any,
      exec: async (file, args) => {
        if (args.includes('interfaces')) {
          return { stdout: 'Idx Met MTU State Name\n 12 25 1500 connected Wi-Fi\n', stderr: '' }
        }
        if (args.includes('show') && args.includes('dns')) {
          return { stdout: 'Statically Configured DNS Servers: 9.9.9.9\n', stderr: '' }
        }
        return { stdout: '', stderr: '' }
      },
    })
    await enf.apply()
    const backup = JSON.parse(readFileSync(join(dir, 'enforcement', 'dns-backup.json'), 'utf-8'))
    expect(backup.method).toBe('netsh')
    expect(backup.targets[0]).toEqual({ name: 'Wi-Fi', mode: 'static', servers: ['9.9.9.9'] })
    await enf.revert()
  })
})
