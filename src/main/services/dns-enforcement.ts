// System-wide DNS enforcement.
//
// Privilege-separated design (see docs/threat-model): all filtering + DoT stays
// in the UNPRIVILEGED app resolver (127.0.0.1:<resolverPort>). Enforcement adds
// two reversible, elevated changes on Linux:
//   1. a tiny privileged helper that binds 127.0.0.1:53 (the low port apps use)
//      and forwards every query to the app resolver,
//   2. /etc/resolv.conf → `nameserver 127.0.0.1` (backed up first).
// Reverting restores resolv.conf and stops the helper. A safety timer
// auto-reverts so a crash/leftover can never permanently hijack DNS.
//
// The helper is launched through the platform's native elevation prompt. It
// never handles policy or upstream TLS; it only forwards loopback DNS traffic.

import { spawn, execFile } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync, existsSync, mkdirSync, unlinkSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import type { ChildProcess } from 'child_process'
import type { EnforcementMethod, EnforcementPlan, EnforcementStatus, EnforcementStep } from '../../shared/enforcement'

const execFileAsync = promisify(execFile)
const RESOLV_CONF = '/etc/resolv.conf'
const LOOPBACK = '127.0.0.1'
const AUTO_REVERT_MS = 10 * 60 * 1000 // 10 minutes safety backstop

const BULWRK_MARKER = 'Written by Bulwrk Network Guard'

export function buildResolvConf(nameserver: string): string {
  return `# ${BULWRK_MARKER} (system-wide DNS enforcement).\n# Original file backed up; disabling protection restores it.\nnameserver ${nameserver}\n`
}

/** True if resolv.conf was written by our enforcement (i.e. potentially stale). */
export function isBulwrkManagedResolvConf(text: string): boolean {
  return text.includes(BULWRK_MARKER)
}

/** Pure: what enforcement would do on a given platform. Used by UI + tests. */
export function buildEnforcementPlan(platform: NodeJS.Platform, resolverPort: number): EnforcementPlan {
  if (platform === 'darwin') {
    const method: EnforcementMethod = 'networksetup'
    return {
      platform, method, requiresElevation: true,
      apply: [
        { describe: 'Start the elevated loopback DNS forwarder on port 53', command: `osascript (administrator) <node> <helper> ${resolverPort}` },
        { describe: 'Point active network services at the local resolver', command: `networksetup -setdnsservers <service> ${LOOPBACK}` },
      ],
      revert: [
        { describe: 'Restore the exact DNS servers saved for each service', command: 'networksetup -setdnsservers <service> <saved servers|Empty>' },
        { describe: 'Stop the elevated loopback DNS forwarder', command: 'kill <helper-pid>' },
      ],
    }
  }
  if (platform === 'win32') {
    const method: EnforcementMethod = 'netsh'
    return {
      platform, method, requiresElevation: true,
      apply: [
        { describe: 'Start the elevated loopback DNS forwarder on port 53', command: `PowerShell Start-Process -Verb RunAs <node> <helper> ${resolverPort}` },
        { describe: 'Point active interfaces at 127.0.0.1 and ::1', command: 'Set-DnsClientServerAddress <interface> 127.0.0.1,::1' },
      ],
      revert: [
        { describe: 'Restore the exact IPv4/IPv6 DNS servers saved for each interface', command: 'Set-DnsClientServerAddress <interface> <saved servers>' },
        { describe: 'Stop the elevated loopback DNS forwarder', command: 'Stop-Process -Id <helper-pid>' },
      ],
    }
  }
  // linux
  const method: EnforcementMethod = 'resolv.conf'
  const apply: EnforcementStep[] = [
    { describe: `Start a privileged helper on ${LOOPBACK}:53 forwarding to the resolver (:${resolverPort})`, command: `pkexec <node> <helper> ${resolverPort}` },
    { describe: `Back up ${RESOLV_CONF}`, command: `cp ${RESOLV_CONF} <backup>` },
    { describe: `Point the system resolver at ${LOOPBACK}`, command: `printf 'nameserver ${LOOPBACK}\\n' | pkexec tee ${RESOLV_CONF}` },
  ]
  const revert: EnforcementStep[] = [
    { describe: `Restore ${RESOLV_CONF} from backup`, command: `cp <backup> ${RESOLV_CONF}` },
    { describe: 'Stop the privileged :53 helper', command: 'kill <helper-pid>' },
  ]
  return { platform, method, requiresElevation: true, apply, revert }
}

/** The privileged helper: binds :53 (UDP+TCP) and relays to the app resolver. */
function helperSource(): string {
  return `'use strict'
// Bulwrk privileged DNS helper: binds 127.0.0.1:53 and forwards to the
// unprivileged app resolver. Minimal by design — no filtering logic here.
const dgram = require('dgram'); const net = require('net')
const PORT = parseInt(process.argv[2], 10) || 5353; const READY = process.argv[3]
function ready(s) { process.stdout.write(s+'\\n'); if (READY) require('fs').appendFileSync(READY, s+'\\n') }
const udp = dgram.createSocket('udp4')
udp.on('message', (msg, rinfo) => {
  const up = dgram.createSocket('udp4')
  const to = setTimeout(() => { try { up.close() } catch {} }, 4000)
  up.on('message', (resp) => { clearTimeout(to); udp.send(resp, rinfo.port, rinfo.address); try { up.close() } catch {} })
  up.on('error', () => { clearTimeout(to); try { up.close() } catch {} })
  up.send(msg, PORT, '127.0.0.1')
})
udp.bind(53, '127.0.0.1', () => ready('helper-udp-ready'))
const udp6 = dgram.createSocket('udp6')
udp6.on('error', () => {})
udp6.on('message', (msg, rinfo) => { const up = dgram.createSocket('udp4'); const to = setTimeout(() => { try { up.close() } catch {} }, 4000); up.on('message', (resp) => { clearTimeout(to); udp6.send(resp, rinfo.port, rinfo.address); try { up.close() } catch {} }); up.on('error', () => { clearTimeout(to); try { up.close() } catch {} }); up.send(msg, PORT, '127.0.0.1') })
udp6.bind(53, '::1', () => ready('helper-udp6-ready'))
const tcp = net.createServer((client) => {
  const upstream = net.connect(PORT, '127.0.0.1')
  client.pipe(upstream); upstream.pipe(client)
  const kill = () => { client.destroy(); upstream.destroy() }
  client.on('error', kill); upstream.on('error', kill)
})
tcp.listen(53, '127.0.0.1', () => ready('helper-tcp-ready'))
const tcp6 = net.createServer((client) => { const upstream = net.connect(PORT, '127.0.0.1'); client.pipe(upstream); upstream.pipe(client); const kill = () => { client.destroy(); upstream.destroy() }; client.on('error', kill); upstream.on('error', kill) })
tcp6.on('error', () => {})
tcp6.listen(53, '::1', () => ready('helper-tcp6-ready'))
`
}

type WindowsDnsEntry = { InterfaceIndex: number; InterfaceAlias: string; AddressFamily: number; ServerAddresses: string[] }
type MacDnsEntry = { service: string; servers: string[] }
type PlatformDnsState = { platform: 'win32' | 'darwin'; windows?: WindowsDnsEntry[]; mac?: MacDnsEntry[] }

export function parseWindowsDnsEntries(json: string): WindowsDnsEntry[] {
  if (!json.trim()) return []
  const value = JSON.parse(json)
  const rows = Array.isArray(value) ? value : [value]
  return rows.flatMap((row) => {
    const servers = Array.isArray(row.ServerAddresses) ? row.ServerAddresses.map(String).filter(Boolean) : []
    const index = Number(row.InterfaceIndex)
    const family = Number(row.AddressFamily)
    return Number.isInteger(index) && (family === 2 || family === 23) && servers.length
      ? [{ InterfaceIndex: index, InterfaceAlias: String(row.InterfaceAlias ?? ''), AddressFamily: family, ServerAddresses: servers }]
      : []
  })
}

export function parseMacDnsServices(listOutput: string, dnsByService: Record<string, string>): MacDnsEntry[] {
  return listOutput.split(/\r?\n/).map((service) => service.trim()).filter((service) => service && !service.startsWith('*') && Object.prototype.hasOwnProperty.call(dnsByService, service))
    .map((service) => ({ service, servers: (dnsByService[service] ?? '').split(/\s+/).filter((server) => /^((\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+)$/i.test(server)) }))
}

function psQuote(value: string): string { return "'" + value.replace(/'/g, "''") + "'" }
function shellQuote(value: string): string { return "'" + value.replace(/'/g, "'\\''") + "'" }

async function elevatedMacShell(command: string, prompt: string): Promise<string> {
  const script = `do shell script ${JSON.stringify(command)} with prompt ${JSON.stringify(prompt)} with administrator privileges`
  const { stdout } = await execFileAsync('/usr/bin/osascript', ['-e', script], { timeout: 30_000 })
  return stdout
}

async function powershell(command: string, elevated = false): Promise<string> {
  if (!elevated) {
    const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], { timeout: 15_000, windowsHide: true })
    return stdout
  }
  const wrapped = `$p = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',${psQuote(command)} -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`
  const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', wrapped], { timeout: 30_000, windowsHide: true })
  return stdout
}

interface EnforcementDeps {
  /** Whether the app resolver is currently running (precondition). */
  isResolverRunning: () => boolean
  /** The resolver's port to forward to. */
  resolverPort: () => number
  /** Audit sink. */
  audit: (event: string, detail?: string) => void
}

export class DnsEnforcement {
  private enforcing = false
  private since: string | null = null
  private method: EnforcementMethod | null = null
  private helper: ChildProcess | null = null
  private helperPid: number | null = null
  private readyPath: string | null = null
  private platformState: PlatformDnsState | null = null
  private backupPath: string | null = null
  private autoRevertTimer: ReturnType<typeof setTimeout> | null = null
  private autoRevertAt: string | null = null
  private message: string | null = null

  constructor(private deps: EnforcementDeps) {}

  getStatus(): EnforcementStatus {
    return {
      enforcing: this.enforcing,
      method: this.method,
      since: this.since,
      autoRevertAt: this.autoRevertAt,
      message: this.message,
    }
  }

  private dataDir(): string {
    const dir = join(app.getPath('userData'), 'enforcement')
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    return dir
  }

  private statePath(): string { return join(this.dataDir(), 'dns-settings.json') }

  private async queryWindowsDns(): Promise<WindowsDnsEntry[]> {
    const output = await powershell("Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress")
    return parseWindowsDnsEntries(output)
  }

  private async queryMacDns(): Promise<MacDnsEntry[]> {
    const { stdout: services } = await execFileAsync('/usr/sbin/networksetup', ['-listallnetworkservices'], { timeout: 10_000 })
    const dns: Record<string, string> = {}
    for (const service of services.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith('*'))) {
      try {
        const { stdout: info } = await execFileAsync('/usr/sbin/networksetup', ['-getinfo', service], { timeout: 5_000 })
        if (/^IP address:\s+none$/im.test(info) && /^IPv6 IP address:\s+none$/im.test(info)) continue
        const { stdout } = await execFileAsync('/usr/sbin/networksetup', ['-getdnsservers', service], { timeout: 5_000 })
        dns[service] = stdout
      } catch { /* an unavailable service is not an active target */ }
    }
    return parseMacDnsServices(services, dns)
  }

  private async startElevatedHelper(port: number): Promise<boolean> {
    const helperPath = join(this.dataDir(), 'dns-helper.cjs')
    this.readyPath = join(this.dataDir(), 'dns-helper.ready')
    try { unlinkSync(this.readyPath) } catch { /* absent */ }
    writeFileSync(helperPath, helperSource(), 'utf-8')
    const node = await resolveNodeBinary(process.execPath && !process.execPath.includes('electron') ? process.execPath : 'node')
    if (process.platform === 'linux') {
      this.helper = spawn('pkexec', [node, helperPath, String(port), this.readyPath], { stdio: ['ignore', 'pipe', 'pipe'] })
      return waitForHelper(this.helper, this.readyPath)
    }
    if (process.platform === 'darwin') {
      const command = `nohup ${shellQuote(node)} ${shellQuote(helperPath)} ${port} ${shellQuote(this.readyPath)} >/dev/null 2>&1 & echo $!`
      const output = await elevatedMacShell(command, 'Bulwrk needs administrator permission to protect system DNS.')
      this.helperPid = Number(output.trim().split(/\s+/).pop()) || null
      return waitForHelper(null, this.readyPath)
    }
    const command = `$p = Start-Process -FilePath ${psQuote(node)} -ArgumentList ${psQuote(helperPath)},${psQuote(String(port))},${psQuote(this.readyPath)} -Verb RunAs -WindowStyle Hidden -PassThru; $p.Id`
    const output = await powershell(command, true)
    this.helperPid = Number(output.trim().split(/\s+/).pop()) || null
    return waitForHelper(null, this.readyPath)
  }

  /**
   * On startup, clean up enforcement orphaned by a previous run: if resolv.conf
   * still carries our marker but we aren't enforcing, an app restart lost the
   * auto-revert timer and left DNS redirected. Restore the backup and kill any
   * stale :53 helper so a crash/restart can never permanently hijack DNS.
   */
  async reconcileOnStartup(): Promise<void> {
    if (this.enforcing) return
    if (process.platform === 'darwin' || process.platform === 'win32') {
      const stateFile = this.statePath()
      if (!existsSync(stateFile)) return
      try {
        const state = JSON.parse(readFileSync(stateFile, 'utf8')) as PlatformDnsState
        if (state.platform === process.platform) {
          await this.restorePlatformState(state)
          try { unlinkSync(stateFile) } catch { /* already removed */ }
          await this.killStaleHelpers()
          this.deps.audit('enforcement_reconciled', 'restored stale system DNS settings from a previous run')
        }
      } catch { /* best effort: leave the state for the next explicit attempt */ }
      return
    }
    try {
      const current = readFileSync(RESOLV_CONF, 'utf-8')
      if (!isBulwrkManagedResolvConf(current)) return
      const backup = join(this.dataDir(), 'resolv.conf.backup')
      if (existsSync(backup)) {
        await execFileAsync('pkexec', ['cp', backup, RESOLV_CONF])
      }
      await this.killStaleHelpers()
      this.deps.audit('enforcement_reconciled', 'cleaned up stale enforcement from a previous run')
    } catch { /* best effort */ }
  }

  private async killStaleHelpers(): Promise<void> {
    if (process.platform === 'darwin') {
      try { await elevatedMacShell("pkill -f 'dns-helper.cjs' || true", 'Bulwrk needs administrator permission to clean up DNS protection.') } catch { /* ignore */ }
      return
    }
    if (process.platform === 'win32') {
      try { await powershell("Get-CimInstance Win32_Process -Filter \"Name = 'node.exe'\" | Where-Object { $_.CommandLine -like '*dns-helper.cjs*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }", true) } catch { /* ignore */ }
      return
    }
    try {
      const { stdout } = await execFileAsync('bash', ['-lc', "ps -eo pid,args | grep 'dns-helper.cjs' | grep -v grep | awk '{print $1}'"])
      for (const pid of stdout.split(/\s+/).filter(Boolean)) {
        try { await execFileAsync('pkexec', ['kill', pid]) } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  }

  async apply(): Promise<EnforcementStatus> {
    if (this.enforcing) return this.getStatus()
    // Precondition: the app resolver must be running to forward to.
    if (!this.deps.isResolverRunning()) {
      this.message = 'Start the Secure DNS resolver before enabling system-wide protection.'
      return this.getStatus()
    }

    const port = this.deps.resolverPort()

    if (process.platform === 'darwin' || process.platform === 'win32') {
      try {
        this.platformState = process.platform === 'darwin'
          ? { platform: 'darwin', mac: await this.queryMacDns() }
          : { platform: 'win32', windows: await this.queryWindowsDns() }
        if (!(this.platformState.mac?.length || this.platformState.windows?.length)) {
          this.message = 'No active network DNS settings were found to protect.'
          return this.getStatus()
        }
        writeFileSync(this.statePath(), JSON.stringify(this.platformState), 'utf8')
        if (!await this.startElevatedHelper(port)) {
          this.stopHelper()
          this.message = 'Could not bind the local DNS port 53. Approve the administrator prompt and check whether another DNS service is using it.'
          return this.getStatus()
        }
        await this.setPlatformLoopback(this.platformState)
        this.enforcing = true
        this.method = process.platform === 'darwin' ? 'networksetup' : 'netsh'
        this.since = new Date().toISOString()
        this.message = null
        this.deps.audit('enforcement_applied', `${this.method} DNS → loopback, helper :53 → :${port}`)
        this.armSafetyTimer()
        return this.getStatus()
      } catch (err) {
        await this.restorePlatformState(this.platformState)
        this.stopHelper()
        this.message = `Failed to update system DNS: ${err instanceof Error ? err.message : err}`
        return this.getStatus()
      }
    }

    const nodePath = process.execPath && !process.execPath.includes('electron') ? process.execPath : 'node'
    // In dev, process.execPath is electron; fall back to a node on PATH.
    const node = await resolveNodeBinary(nodePath)

    // 1. Write + launch the privileged :53 helper.
    const helperPath = join(this.dataDir(), 'dns-helper.cjs')
    writeFileSync(helperPath, helperSource(), 'utf-8')
    try {
    this.helper = spawn('pkexec', [node, helperPath, String(port), this.readyPath], { stdio: ['ignore', 'pipe', 'pipe'] })
    } catch (err) {
      this.message = `Failed to launch privileged helper: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }
    const ready = await waitForHelper(this.helper, this.readyPath)
    if (!ready) {
      this.stopHelper()
      this.message = 'Could not bind 127.0.0.1:53. Approve the system authentication prompt and ensure no other DNS service owns port 53.'
      return this.getStatus()
    }

    // 2. Back up and rewrite resolv.conf (elevated).
    this.backupPath = join(this.dataDir(), 'resolv.conf.backup')
    try {
      await execFileAsync('pkexec', ['cp', RESOLV_CONF, this.backupPath])
      await writeResolvConf(buildResolvConf(LOOPBACK))
    } catch (err) {
      this.stopHelper()
      this.message = `Failed to update ${RESOLV_CONF}: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }

    this.enforcing = true
    this.method = 'resolv.conf'
    this.since = new Date().toISOString()
    this.message = null
    this.deps.audit('enforcement_applied', `resolv.conf → ${LOOPBACK}, helper :53 → :${port}`)

    // 3. Safety auto-revert.
    this.armSafetyTimer()

    return this.getStatus()
  }

  async revert(reason = 'user'): Promise<EnforcementStatus> {
    if (this.autoRevertTimer) { clearTimeout(this.autoRevertTimer); this.autoRevertTimer = null }
    this.autoRevertAt = null

    if (this.platformState) {
      await this.restorePlatformState(this.platformState)
      try { unlinkSync(this.statePath()) } catch { /* already removed */ }
    } else if (this.backupPath && existsSync(this.backupPath)) {
      try { await execFileAsync('pkexec', ['cp', this.backupPath, RESOLV_CONF]) }
      catch (err) { this.message = `Failed to restore ${RESOLV_CONF}: ${err instanceof Error ? err.message : err}` }
    }
    this.stopHelper()

    if (this.enforcing) this.deps.audit('enforcement_reverted', reason)
    this.enforcing = false
    this.method = null
    this.since = null
    this.platformState = null
    return this.getStatus()
  }

  private armSafetyTimer(): void {
    this.autoRevertAt = new Date(Date.now() + AUTO_REVERT_MS).toISOString()
    this.autoRevertTimer = setTimeout(() => { void this.revert('auto-revert') }, AUTO_REVERT_MS)
  }

  private async setPlatformLoopback(state: PlatformDnsState): Promise<void> {
    if (state.platform === 'darwin') {
      const commands = (state.mac ?? []).map(({ service }) => `/usr/sbin/networksetup -setdnsservers ${shellQuote(service)} ${LOOPBACK}`)
      await elevatedMacShell(commands.join(' && '), 'Bulwrk needs administrator permission to protect system DNS.')
      return
    }
    const commands = (state.windows ?? []).map(({ InterfaceIndex, AddressFamily }) => {
      const address = AddressFamily === 23 ? '::1' : LOOPBACK
      return `Set-DnsClientServerAddress -InterfaceIndex ${InterfaceIndex} -AddressFamily ${AddressFamily === 23 ? 'IPv6' : 'IPv4'} -ServerAddresses ${psQuote(address)}`
    })
    await powershell(`$ErrorActionPreference='Stop'; ${commands.join('; ')}`, true)
  }

  private async restorePlatformState(state: PlatformDnsState | null): Promise<void> {
    if (!state) return
    try {
      if (state.platform === 'darwin') {
        const commands = (state.mac ?? []).map(({ service, servers }) => `/usr/sbin/networksetup -setdnsservers ${shellQuote(service)} ${servers.length ? servers.map(shellQuote).join(' ') : 'Empty'}`)
        if (commands.length) await elevatedMacShell(commands.join(' && '), 'Bulwrk needs administrator permission to restore DNS settings.')
      } else {
        const commands = (state.windows ?? []).map(({ InterfaceIndex, AddressFamily, ServerAddresses }) => ServerAddresses.length
          ? `Set-DnsClientServerAddress -InterfaceIndex ${InterfaceIndex} -AddressFamily ${AddressFamily === 23 ? 'IPv6' : 'IPv4'} -ServerAddresses ${ServerAddresses.map(psQuote).join(',')}`
          : `Set-DnsClientServerAddress -InterfaceIndex ${InterfaceIndex} -AddressFamily ${AddressFamily === 23 ? 'IPv6' : 'IPv4'} -ResetServerAddresses`)
        if (commands.length) await powershell(`$ErrorActionPreference='Stop'; ${commands.join('; ')}`, true)
      }
    } catch (err) {
      this.message = `Failed to restore saved DNS settings: ${err instanceof Error ? err.message : err}`
    }
  }

  private stopHelper(): void {
    if (this.helper && this.helper.pid) {
      // The helper runs under pkexec; kill the pkexec child tree.
      try { spawn('pkexec', ['kill', String(this.helper.pid)]) } catch { /* ignore */ }
      try { this.helper.kill() } catch { /* ignore */ }
    }
    if (this.helperPid) {
      if (process.platform === 'darwin') void elevatedMacShell(`/bin/kill ${this.helperPid}`, 'Bulwrk needs administrator permission to stop DNS protection.').catch(() => {})
      if (process.platform === 'win32') void powershell(`Stop-Process -Id ${this.helperPid} -Force -ErrorAction SilentlyContinue`, true).catch(() => {})
    }
    this.helper = null
    this.helperPid = null
    this.readyPath = null
  }
}

async function resolveNodeBinary(preferred: string): Promise<string> {
  if (preferred && preferred !== 'node' && !preferred.includes('electron')) return preferred
  try {
    if (process.platform === 'win32') {
      const { stdout } = await execFileAsync('where.exe', ['node.exe'])
      const p = stdout.split(/\r?\n/).map((line) => line.trim()).find(Boolean)
      if (p) return p
      return 'node.exe'
    }
    const { stdout } = await execFileAsync('bash', ['-lc', 'command -v node'])
    const p = stdout.trim()
    if (p) return p
  } catch { /* ignore */ }
  return 'node'
}

function waitForHelper(child: ChildProcess | null, readyPath: string | null): Promise<boolean> {
  return new Promise((resolve) => {
    let udpReady = false
    const check = () => {
      if (readyPath && existsSync(readyPath) && readFileSync(readyPath, 'utf8').includes('helper-udp-ready')) {
        udpReady = true
        resolve(true)
      }
    }
    const interval = setInterval(check, 100)
    const timer = setTimeout(() => { clearInterval(interval); resolve(udpReady) }, 4000)
    child?.stdout?.on('data', (d: Buffer) => {
      if (d.toString().includes('helper-udp-ready')) {
        udpReady = true
        clearInterval(interval)
        clearTimeout(timer)
        resolve(true)
      }
    })
    child?.on('exit', () => { clearInterval(interval); clearTimeout(timer); resolve(false) })
    child?.on('error', () => { clearInterval(interval); clearTimeout(timer); resolve(false) })
  })
}

/** Write resolv.conf via an elevated `tee` (root-owned file). */
function writeResolvConf(contents: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('pkexec', ['tee', RESOLV_CONF], { stdio: ['pipe', 'ignore', 'pipe'] })
    child.on('error', reject)
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`tee exited ${code}`))))
    child.stdin?.write(contents)
    child.stdin?.end()
  })
}
