// System-wide DNS enforcement.
//
// Privilege-separated design (see docs/threat-model): all filtering + DoT stays
// in the UNPRIVILEGED app resolver (127.0.0.1:<resolverPort>). Enforcement adds
// reversible, elevated changes:
//   1. a tiny privileged helper that binds 127.0.0.1:53 and forwards to the app resolver,
//   2. OS DNS → 127.0.0.1 (Linux: resolv.conf; macOS: networksetup; Windows: netsh).
// Reverting restores the backup and stops the helper. A safety timer auto-reverts
// so a crash/leftover can never permanently hijack DNS.
//
// Device-policy / remote isolate MUST NOT call this — loopback DoT only.

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

const BULWARK_MARKER = 'Written by Bulwark Network Guard'

export function buildResolvConf(nameserver: string): string {
  return `# ${BULWARK_MARKER} (system-wide DNS enforcement).\n# Original file backed up; disabling protection restores it.\nnameserver ${nameserver}\n`
}

/** True if resolv.conf was written by our enforcement (i.e. potentially stale). */
export function isBulwarkManagedResolvConf(text: string): boolean {
  return text.includes(BULWARK_MARKER)
}

/** Parse `networksetup -listallnetworkservices` — skip header and disabled (* ) lines. */
export function parseNetworkServices(stdout: string): string[] {
  const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  const out: string[] = []
  for (const line of lines) {
    if (/^An asterisk/i.test(line)) continue
    if (line.startsWith('*')) continue // disabled
    out.push(line)
  }
  return out
}

/**
 * Prefer active hardware ports. Skip common VPN/bridge names unless nothing else
 * remains (then return all enumerated services).
 */
export function selectDarwinDnsTargets(services: string[]): string[] {
  const skip = /vpn|bridge|thunderbolt|iphone|ipad|bluetooth|awdl|llw|utun|vmnet|veth/i
  const preferred = services.filter((s) => !skip.test(s))
  return preferred.length > 0 ? preferred : services
}

/**
 * Parse `netsh interface ipv4 show interfaces` style tables.
 * Typical columns: Idx Met MTU State Name
 */
export function parseNetshInterfaces(stdout: string): Array<{ name: string; connected: boolean }> {
  const lines = stdout.split(/\r?\n/)
  const results: Array<{ name: string; connected: boolean }> = []
  for (const raw of lines) {
    const line = raw.trimEnd()
    if (!line.trim()) continue
    if (/Interface Name|^\s*Idx\b|^-+$/i.test(line.trim())) continue
    // Idx Met MTU State Name
    const m = line.match(/^\s*\d+\s+\d+\s+\d+\s+(\S+)\s+(.+)$/)
    if (m) {
      results.push({ name: m[2].trim(), connected: /^connected$/i.test(m[1]) })
      continue
    }
    // Loose fallback: "... connected   Wi-Fi"
    const m2 = line.match(/\b(connected|disconnected)\b\s+(.+)$/i)
    if (m2) {
      results.push({ name: m2[2].trim(), connected: /^connected$/i.test(m2[1]) })
    }
  }
  return results
}

export function selectWinDnsTargets(ifaces: Array<{ name: string; connected: boolean }>): string[] {
  const skip = /loopback|vethernet|virtual|hyper-v|docker|wsl|isatap|teredo|6to4/i
  const connected = ifaces.filter((i) => i.connected && !skip.test(i.name))
  if (connected.length > 0) return connected.map((i) => i.name)
  return ifaces.filter((i) => !skip.test(i.name)).map((i) => i.name)
}

/** Parse `networksetup -getdnsservers` output. */
export function parseDarwinDnsServers(stdout: string): string[] | 'dhcp' {
  const text = stdout.trim()
  if (!text || /aren't any DNS Servers/i.test(text) || /^Empty$/i.test(text)) return 'dhcp'
  return text.split(/\r?\n/).map((l) => l.trim()).filter((l) => /^\d{1,3}(?:\.\d{1,3}){3}$/.test(l) || l.includes(':'))
}

/** Parse simple `netsh interface ip show dns` / PowerShell-ish server lists. */
export function parseWinDnsServers(stdout: string): { mode: 'dhcp' | 'static'; servers: string[] } {
  const text = stdout
  if (/DHCP/i.test(text) && /Yes|Configured|Statically Configured DNS Servers:\s*$/im.test(text) === false) {
    // Prefer explicit static list when present
  }
  const servers: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)
    if (m) servers.push(m[1])
  }
  const dhcp = /DNS servers configured through DHCP/i.test(text)
    || (/DHCP/i.test(text) && servers.length === 0)
  if (dhcp && servers.length === 0) return { mode: 'dhcp', servers: [] }
  if (servers.length === 0) return { mode: 'dhcp', servers: [] }
  return { mode: 'static', servers }
}

export interface DnsTargetBackup {
  name: string
  /** macOS: 'dhcp' means Empty; Windows: dhcp vs static list */
  mode: 'dhcp' | 'static'
  servers: string[]
}

export interface DnsBackupFile {
  platform: NodeJS.Platform
  method: EnforcementMethod
  createdAt: string
  targets: DnsTargetBackup[]
  /** Linux only — path to resolv.conf backup copy */
  resolvBackupPath?: string
}

/** Pure: what enforcement would do on a given platform. Used by UI + tests. */
export function buildEnforcementPlan(
  platform: NodeJS.Platform,
  resolverPort: number,
  targets: string[] = [],
): EnforcementPlan {
  const sample = targets[0] || (platform === 'darwin' ? '<service>' : platform === 'win32' ? '<iface>' : '')
  if (platform === 'darwin') {
    const method: EnforcementMethod = 'networksetup'
    const svcList = targets.length > 0 ? targets.map((t) => `"${t}"`).join(', ') : '<active services>'
    const apply: EnforcementStep[] = [
      { describe: `Start a privileged helper on ${LOOPBACK}:53 forwarding to the resolver (:${resolverPort})`, command: `sudo <node> <helper> ${resolverPort}` },
      { describe: `Back up DNS for ${svcList}`, command: `networksetup -getdnsservers ${sample}` },
      { describe: `Point network service DNS at ${LOOPBACK}`, command: `sudo networksetup -setdnsservers ${sample} ${LOOPBACK}` },
    ]
    const revert: EnforcementStep[] = [
      { describe: 'Restore previous DNS (Empty = DHCP)', command: `sudo networksetup -setdnsservers ${sample} Empty` },
      { describe: 'Stop the privileged :53 helper', command: 'sudo kill <helper-pid>' },
    ]
    return { platform, method, requiresElevation: true, apply, revert }
  }
  if (platform === 'win32') {
    const method: EnforcementMethod = 'netsh'
    const apply: EnforcementStep[] = [
      { describe: `Start a privileged helper on ${LOOPBACK}:53 forwarding to the resolver (:${resolverPort})`, command: `<elevated> <node> <helper> ${resolverPort}` },
      { describe: `Back up DNS for ${sample || '<iface>'}`, command: `netsh interface ip show dns name="${sample || '<iface>'}"` },
      { describe: `Set interface DNS to ${LOOPBACK}`, command: `netsh interface ip set dns name="${sample || '<iface>'}" static ${LOOPBACK} validate=no` },
    ]
    const revert: EnforcementStep[] = [
      { describe: 'Restore DHCP or previous static DNS', command: `netsh interface ip set dns name="${sample || '<iface>'}" dhcp` },
      { describe: 'Stop the privileged :53 helper', command: 'kill <helper-pid>' },
    ]
    return { platform, method, requiresElevation: true, apply, revert }
  }
  // linux
  const method: EnforcementMethod = 'resolv.conf'
  const apply: EnforcementStep[] = [
    { describe: `Start a privileged helper on ${LOOPBACK}:53 forwarding to the resolver (:${resolverPort})`, command: `sudo <node> <helper> ${resolverPort}` },
    { describe: `Back up ${RESOLV_CONF}`, command: `cp ${RESOLV_CONF} <backup>` },
    { describe: `Point the system resolver at ${LOOPBACK}`, command: `printf 'nameserver ${LOOPBACK}\\n' | sudo tee ${RESOLV_CONF}` },
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
// Bulwark privileged DNS helper: binds 127.0.0.1:53 and forwards to the
// unprivileged app resolver. Minimal by design — no filtering logic here.
const dgram = require('dgram'); const net = require('net')
const PORT = parseInt(process.argv[2], 10) || 5353
const udp = dgram.createSocket('udp4')
udp.on('message', (msg, rinfo) => {
  const up = dgram.createSocket('udp4')
  const to = setTimeout(() => { try { up.close() } catch {} }, 4000)
  up.on('message', (resp) => { clearTimeout(to); udp.send(resp, rinfo.port, rinfo.address); try { up.close() } catch {} })
  up.on('error', () => { clearTimeout(to); try { up.close() } catch {} })
  up.send(msg, PORT, '127.0.0.1')
})
udp.bind(53, '127.0.0.1', () => process.stdout.write('helper-udp-ready\\n'))
const tcp = net.createServer((client) => {
  const upstream = net.connect(PORT, '127.0.0.1')
  client.pipe(upstream); upstream.pipe(client)
  const kill = () => { client.destroy(); upstream.destroy() }
  client.on('error', kill); upstream.on('error', kill)
})
tcp.listen(53, '127.0.0.1', () => process.stdout.write('helper-tcp-ready\\n'))
`
}

export type ExecFn = (
  file: string,
  args: string[],
  opts?: { timeout?: number; windowsHide?: boolean },
) => Promise<{ stdout: string; stderr: string }>

export type SpawnElevatedFn = (
  node: string,
  helperPath: string,
  port: number,
) => ChildProcess

interface EnforcementDeps {
  /** Whether the app resolver is currently running (precondition). */
  isResolverRunning: () => boolean
  /** The resolver's port to forward to. */
  resolverPort: () => number
  /** Audit sink. */
  audit: (event: string, detail?: string) => void
  /** Override for tests. */
  platform?: () => NodeJS.Platform
  exec?: ExecFn
  spawnElevated?: SpawnElevatedFn
  /** Override userData root for tests. */
  dataDir?: () => string
}

export class DnsEnforcement {
  private enforcing = false
  private since: string | null = null
  private method: EnforcementMethod | null = null
  private helper: ChildProcess | null = null
  private backupPath: string | null = null
  private targets: string[] = []
  private autoRevertTimer: ReturnType<typeof setTimeout> | null = null
  private autoRevertAt: string | null = null
  private message: string | null = null

  constructor(private deps: EnforcementDeps) {}

  private platform(): NodeJS.Platform {
    return this.deps.platform?.() ?? process.platform
  }

  private exec: ExecFn = async (file, args, opts) => {
    if (this.deps.exec) return this.deps.exec(file, args, opts)
    const result = await execFileAsync(file, args, { encoding: 'utf-8', ...opts })
    return { stdout: String(result.stdout), stderr: String(result.stderr) }
  }

  getStatus(): EnforcementStatus {
    return {
      enforcing: this.enforcing,
      method: this.method,
      since: this.since,
      autoRevertAt: this.autoRevertAt,
      message: this.message,
      targets: this.targets.length > 0 ? [...this.targets] : undefined,
    }
  }

  private dataDir(): string {
    if (this.deps.dataDir) return this.deps.dataDir()
    const dir = join(app.getPath('userData'), 'enforcement')
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    return dir
  }

  private backupJsonPath(): string {
    return join(this.dataDir(), 'dns-backup.json')
  }

  private lockPath(): string {
    return join(this.dataDir(), 'enforcing.lock')
  }

  /**
   * On startup, clean up enforcement orphaned by a previous run so a crash
   * can never permanently hijack DNS.
   */
  async reconcileOnStartup(): Promise<void> {
    if (this.enforcing) return
    const plat = this.platform()
    try {
      if (plat === 'linux') {
        const current = readFileSync(RESOLV_CONF, 'utf-8')
        if (!isBulwarkManagedResolvConf(current)) return
        const backup = join(this.dataDir(), 'resolv.conf.backup')
        if (existsSync(backup)) {
          await this.exec('sudo', ['-n', 'cp', backup, RESOLV_CONF])
        }
        await this.killStaleHelpers()
        this.deps.audit('enforcement_reconciled', 'cleaned up stale Linux enforcement from a previous run')
        return
      }

      if (!existsSync(this.lockPath()) && !existsSync(this.backupJsonPath())) return
      const backup = this.readBackupFile()
      if (backup) {
        await this.restoreFromBackup(backup)
      }
      await this.killStaleHelpers()
      try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
      try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }
      this.deps.audit('enforcement_reconciled', `cleaned up stale ${plat} enforcement from a previous run`)
    } catch { /* best effort */ }
  }

  private readBackupFile(): DnsBackupFile | null {
    try {
      if (!existsSync(this.backupJsonPath())) return null
      return JSON.parse(readFileSync(this.backupJsonPath(), 'utf-8')) as DnsBackupFile
    } catch {
      return null
    }
  }

  private writeBackupFile(backup: DnsBackupFile): void {
    writeFileSync(this.backupJsonPath(), JSON.stringify(backup, null, 2), 'utf-8')
    writeFileSync(this.lockPath(), backup.createdAt, 'utf-8')
  }

  private async killStaleHelpers(): Promise<void> {
    const plat = this.platform()
    try {
      if (plat === 'win32') {
        await this.exec('taskkill', ['/F', '/IM', 'node.exe', '/FI', 'WINDOWTITLE eq dns-helper*']).catch(() => ({ stdout: '', stderr: '' }))
        // Best-effort: also try wmic / powershell for our helper script
        await this.exec('powershell.exe', [
          '-NoProfile', '-NonInteractive', '-Command',
          "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'dns-helper\\.cjs' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }",
        ]).catch(() => ({ stdout: '', stderr: '' }))
        return
      }
      const { stdout } = await this.exec('bash', ['-lc', "ps -eo pid,args | grep 'dns-helper.cjs' | grep -v grep | awk '{print $1}'"])
      for (const pid of stdout.split(/\s+/).filter(Boolean)) {
        try {
          if (plat === 'darwin') await this.exec('sudo', ['-n', 'kill', pid])
          else await this.exec('sudo', ['-n', 'kill', pid])
        } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  }

  async apply(): Promise<EnforcementStatus> {
    if (this.enforcing) return this.getStatus()
    if (!this.deps.isResolverRunning()) {
      this.message = 'Start the Secure DNS resolver before enabling system-wide protection.'
      return this.getStatus()
    }

    const plat = this.platform()
    if (plat === 'linux') return this.applyLinux()
    if (plat === 'darwin') return this.applyDarwin()
    if (plat === 'win32') return this.applyWin32()
    this.message = `System DNS enforcement is not supported on ${plat}.`
    return this.getStatus()
  }

  private async startHelper(port: number): Promise<boolean> {
    const nodePath = process.execPath && !process.execPath.includes('electron') ? process.execPath : 'node'
    const node = await resolveNodeBinary(nodePath, this.exec)
    const helperPath = join(this.dataDir(), 'dns-helper.cjs')
    writeFileSync(helperPath, helperSource(), 'utf-8')

    try {
      if (this.deps.spawnElevated) {
        this.helper = this.deps.spawnElevated(node, helperPath, port)
      } else if (this.platform() === 'win32') {
        // Prefer starting without UAC prompt when already elevated; otherwise spawn and hope.
        this.helper = spawn(node, [helperPath, String(port)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
      } else {
        this.helper = spawn('sudo', ['-n', node, helperPath, String(port)], { stdio: ['ignore', 'pipe', 'pipe'] })
      }
    } catch (err) {
      this.message = `Failed to launch privileged helper: ${err instanceof Error ? err.message : err}`
      return false
    }
    const ready = await waitForHelper(this.helper)
    if (!ready) {
      this.stopHelper()
      this.message = 'Could not bind 127.0.0.1:53 (elevation required). Enable passwordless privilege or run as administrator.'
      return false
    }
    return true
  }

  private async applyLinux(): Promise<EnforcementStatus> {
    const port = this.deps.resolverPort()
    if (!(await this.startHelper(port))) return this.getStatus()

    this.backupPath = join(this.dataDir(), 'resolv.conf.backup')
    try {
      await this.exec('sudo', ['-n', 'cp', RESOLV_CONF, this.backupPath])
      await writeResolvConf(buildResolvConf(LOOPBACK))
    } catch (err) {
      this.stopHelper()
      this.message = `Failed to update ${RESOLV_CONF}: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }

    return this.markEnforcing('resolv.conf', port, [])
  }

  private async applyDarwin(): Promise<EnforcementStatus> {
    const port = this.deps.resolverPort()
    let services: string[]
    try {
      const { stdout } = await this.exec('networksetup', ['-listallnetworkservices'])
      services = selectDarwinDnsTargets(parseNetworkServices(stdout))
    } catch (err) {
      this.message = `Failed to list network services: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }
    if (services.length === 0) {
      this.message = 'No network services found to enforce DNS on.'
      return this.getStatus()
    }

    // Backup BEFORE helper/DNS mutation
    const targets: DnsTargetBackup[] = []
    for (const name of services) {
      try {
        const { stdout } = await this.exec('networksetup', ['-getdnsservers', name])
        const parsed = parseDarwinDnsServers(stdout)
        targets.push(parsed === 'dhcp'
          ? { name, mode: 'dhcp', servers: [] }
          : { name, mode: 'static', servers: parsed })
      } catch (err) {
        this.message = `Failed to back up DNS for “${name}”: ${err instanceof Error ? err.message : err}`
        return this.getStatus()
      }
    }
    this.writeBackupFile({
      platform: 'darwin',
      method: 'networksetup',
      createdAt: new Date().toISOString(),
      targets,
    })

    if (!(await this.startHelper(port))) {
      try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }
      try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
      return this.getStatus()
    }

    const applied: string[] = []
    try {
      for (const name of services) {
        await this.exec('sudo', ['-n', 'networksetup', '-setdnsservers', name, LOOPBACK])
        applied.push(name)
      }
    } catch (err) {
      // Partial apply → restore what we changed
      await this.restoreDarwinTargets(targets.filter((t) => applied.includes(t.name)))
      this.stopHelper()
      try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }
      try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
      this.message = `Failed to set DNS: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }

    this.targets = services
    return this.markEnforcing('networksetup', port, services)
  }

  private async applyWin32(): Promise<EnforcementStatus> {
    const port = this.deps.resolverPort()
    let ifaces: Array<{ name: string; connected: boolean }>
    try {
      const { stdout } = await this.exec('netsh', ['interface', 'ipv4', 'show', 'interfaces'], { windowsHide: true })
      ifaces = parseNetshInterfaces(stdout)
    } catch (err) {
      this.message = `Failed to list network interfaces: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }
    const names = selectWinDnsTargets(ifaces)
    if (names.length === 0) {
      this.message = 'No network interfaces found to enforce DNS on.'
      return this.getStatus()
    }

    const targets: DnsTargetBackup[] = []
    for (const name of names) {
      try {
        const { stdout } = await this.exec('netsh', ['interface', 'ip', 'show', 'dns', `name=${name}`], { windowsHide: true })
        const parsed = parseWinDnsServers(stdout)
        targets.push({ name, mode: parsed.mode, servers: parsed.servers })
      } catch (err) {
        this.message = `Failed to back up DNS for “${name}”: ${err instanceof Error ? err.message : err}`
        return this.getStatus()
      }
    }
    this.writeBackupFile({
      platform: 'win32',
      method: 'netsh',
      createdAt: new Date().toISOString(),
      targets,
    })

    if (!(await this.startHelper(port))) {
      try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }
      try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
      return this.getStatus()
    }

    const applied: string[] = []
    try {
      for (const name of names) {
        await this.exec('netsh', [
          'interface', 'ip', 'set', 'dns', `name=${name}`, 'static', LOOPBACK, 'validate=no',
        ], { windowsHide: true })
        applied.push(name)
      }
    } catch (err) {
      await this.restoreWinTargets(targets.filter((t) => applied.includes(t.name)))
      this.stopHelper()
      try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }
      try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
      this.message = `Failed to set DNS: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }

    this.targets = names
    return this.markEnforcing('netsh', port, names)
  }

  private markEnforcing(method: EnforcementMethod, port: number, targets: string[]): EnforcementStatus {
    this.enforcing = true
    this.method = method
    this.since = new Date().toISOString()
    this.message = null
    this.targets = targets
    this.deps.audit(
      'enforcement_applied',
      targets.length > 0
        ? `${method} → ${LOOPBACK} on [${targets.join(', ')}], helper :53 → :${port}`
        : `${method} → ${LOOPBACK}, helper :53 → :${port}`,
    )
    this.autoRevertAt = new Date(Date.now() + AUTO_REVERT_MS).toISOString()
    this.autoRevertTimer = setTimeout(() => { void this.revert('auto-revert') }, AUTO_REVERT_MS)
    return this.getStatus()
  }

  async revert(reason = 'user'): Promise<EnforcementStatus> {
    if (this.autoRevertTimer) { clearTimeout(this.autoRevertTimer); this.autoRevertTimer = null }
    this.autoRevertAt = null

    const plat = this.platform()
    const backup = this.readBackupFile()

    if (plat === 'linux') {
      const path = this.backupPath || join(this.dataDir(), 'resolv.conf.backup')
      if (existsSync(path)) {
        try { await this.exec('sudo', ['-n', 'cp', path, RESOLV_CONF]) }
        catch (err) { this.message = `Failed to restore ${RESOLV_CONF}: ${err instanceof Error ? err.message : err}` }
      }
    } else if (backup) {
      try {
        await this.restoreFromBackup(backup)
      } catch (err) {
        this.message = `Failed to restore DNS: ${err instanceof Error ? err.message : err}`
      }
    }

    this.stopHelper()
    try { unlinkSync(this.lockPath()) } catch { /* ignore */ }
    try { unlinkSync(this.backupJsonPath()) } catch { /* ignore */ }

    if (this.enforcing) this.deps.audit('enforcement_reverted', reason)
    this.enforcing = false
    this.method = null
    this.since = null
    this.targets = []
    this.backupPath = null
    return this.getStatus()
  }

  private async restoreFromBackup(backup: DnsBackupFile): Promise<void> {
    if (backup.method === 'networksetup' || backup.platform === 'darwin') {
      await this.restoreDarwinTargets(backup.targets)
      return
    }
    if (backup.method === 'netsh' || backup.platform === 'win32') {
      await this.restoreWinTargets(backup.targets)
    }
  }

  private async restoreDarwinTargets(targets: DnsTargetBackup[]): Promise<void> {
    for (const t of targets) {
      if (t.mode === 'dhcp' || t.servers.length === 0) {
        await this.exec('sudo', ['-n', 'networksetup', '-setdnsservers', t.name, 'Empty'])
      } else {
        await this.exec('sudo', ['-n', 'networksetup', '-setdnsservers', t.name, ...t.servers])
      }
    }
  }

  private async restoreWinTargets(targets: DnsTargetBackup[]): Promise<void> {
    for (const t of targets) {
      if (t.mode === 'dhcp' || t.servers.length === 0) {
        await this.exec('netsh', ['interface', 'ip', 'set', 'dns', `name=${t.name}`, 'dhcp'], { windowsHide: true })
      } else {
        await this.exec('netsh', [
          'interface', 'ip', 'set', 'dns', `name=${t.name}`, 'static', t.servers[0], 'validate=no',
        ], { windowsHide: true })
        for (let i = 1; i < t.servers.length; i++) {
          await this.exec('netsh', [
            'interface', 'ip', 'add', 'dns', `name=${t.name}`, t.servers[i], `index=${i + 1}`,
          ], { windowsHide: true }).catch(() => ({ stdout: '', stderr: '' }))
        }
      }
    }
  }

  private stopHelper(): void {
    if (this.helper && this.helper.pid) {
      const plat = this.platform()
      try {
        if (plat === 'win32') {
          // Prefer injected exec in tests; spawn taskkill only when available.
          void this.exec('taskkill', ['/PID', String(this.helper.pid), '/T', '/F'], { windowsHide: true })
            .catch(() => { try { this.helper?.kill() } catch { /* ignore */ } })
        } else {
          spawn('sudo', ['-n', 'kill', String(this.helper.pid)])
        }
      } catch { /* ignore */ }
      try { this.helper.kill() } catch { /* ignore */ }
    }
    this.helper = null
  }
}

async function resolveNodeBinary(preferred: string, exec: ExecFn): Promise<string> {
  if (preferred && preferred !== 'node' && !preferred.includes('electron')) return preferred
  try {
    const { stdout } = await exec('bash', ['-lc', 'command -v node'])
    const p = stdout.trim()
    if (p) return p
  } catch { /* ignore */ }
  return 'node'
}

function waitForHelper(child: ChildProcess): Promise<boolean> {
  return new Promise((resolve) => {
    let udpReady = false
    const timer = setTimeout(() => resolve(udpReady), 4000)
    child.stdout?.on('data', (d: Buffer) => {
      if (d.toString().includes('helper-udp-ready')) {
        udpReady = true
        clearTimeout(timer)
        resolve(true)
      }
    })
    child.on('exit', () => { clearTimeout(timer); resolve(false) })
    child.on('error', () => { clearTimeout(timer); resolve(false) })
  })
}

/** Write resolv.conf via an elevated `tee` (root-owned file). */
function writeResolvConf(contents: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn('sudo', ['-n', 'tee', RESOLV_CONF], { stdio: ['pipe', 'ignore', 'pipe'] })
    child.on('error', reject)
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`tee exited ${code}`))))
    child.stdin?.write(contents)
    child.stdin?.end()
  })
}
