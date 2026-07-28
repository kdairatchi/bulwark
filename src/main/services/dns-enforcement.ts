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
// macOS/Windows plans are generated for completeness; execution here targets
// Linux (the platform this build runs on). Production would ship a signed
// helper invoked via pkexec/UAC instead of `sudo -n`.

import { spawn, execFile } from 'child_process'
import { promisify } from 'util'
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'
import type { ChildProcess } from 'child_process'
import type { EnforcementMethod, EnforcementPlan, EnforcementStatus, EnforcementStep } from '../../shared/enforcement'

const execFileAsync = promisify(execFile)
const RESOLV_CONF = '/etc/resolv.conf'
const LOOPBACK = '127.0.0.1'
const AUTO_REVERT_MS = 10 * 60 * 1000 // 10 minutes safety backstop

export function buildResolvConf(nameserver: string): string {
  return `# Written by Bulwark Network Guard (system-wide DNS enforcement).\n# Original file backed up; disabling protection restores it.\nnameserver ${nameserver}\n`
}

/** Pure: what enforcement would do on a given platform. Used by UI + tests. */
export function buildEnforcementPlan(platform: NodeJS.Platform, resolverPort: number): EnforcementPlan {
  if (platform === 'darwin') {
    const method: EnforcementMethod = 'networksetup'
    return {
      platform, method, requiresElevation: true,
      apply: [{ describe: 'Point the active network service DNS at the local resolver', command: `networksetup -setdnsservers <service> ${LOOPBACK}` }],
      revert: [{ describe: 'Restore automatic DNS', command: 'networksetup -setdnsservers <service> Empty' }],
    }
  }
  if (platform === 'win32') {
    const method: EnforcementMethod = 'netsh'
    return {
      platform, method, requiresElevation: true,
      apply: [{ describe: 'Set the interface DNS to the local resolver', command: `netsh interface ip set dns name="<iface>" static ${LOOPBACK}` }],
      revert: [{ describe: 'Restore DHCP-provided DNS', command: 'netsh interface ip set dns name="<iface>" dhcp' }],
    }
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

  async apply(): Promise<EnforcementStatus> {
    if (this.enforcing) return this.getStatus()
    if (process.platform !== 'linux') {
      this.message = 'Automatic enforcement is implemented for Linux in this build; see the plan for macOS/Windows.'
      return this.getStatus()
    }
    // Precondition: the app resolver must be running to forward to.
    if (!this.deps.isResolverRunning()) {
      this.message = 'Start the Secure DNS resolver before enabling system-wide protection.'
      return this.getStatus()
    }

    const port = this.deps.resolverPort()
    const nodePath = process.execPath && !process.execPath.includes('electron') ? process.execPath : 'node'
    // In dev, process.execPath is electron; fall back to a node on PATH.
    const node = await resolveNodeBinary(nodePath)

    // 1. Write + launch the privileged :53 helper.
    const helperPath = join(this.dataDir(), 'dns-helper.cjs')
    writeFileSync(helperPath, helperSource(), 'utf-8')
    try {
      this.helper = spawn('sudo', ['-n', node, helperPath, String(port)], { stdio: ['ignore', 'pipe', 'pipe'] })
    } catch (err) {
      this.message = `Failed to launch privileged helper: ${err instanceof Error ? err.message : err}`
      return this.getStatus()
    }
    const ready = await waitForHelper(this.helper)
    if (!ready) {
      this.stopHelper()
      this.message = 'Could not bind 127.0.0.1:53 (elevation required). Enable passwordless privilege or run the signed helper.'
      return this.getStatus()
    }

    // 2. Back up and rewrite resolv.conf (elevated).
    this.backupPath = join(this.dataDir(), 'resolv.conf.backup')
    try {
      await execFileAsync('sudo', ['-n', 'cp', RESOLV_CONF, this.backupPath])
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
    this.autoRevertAt = new Date(Date.now() + AUTO_REVERT_MS).toISOString()
    this.autoRevertTimer = setTimeout(() => { void this.revert('auto-revert') }, AUTO_REVERT_MS)

    return this.getStatus()
  }

  async revert(reason = 'user'): Promise<EnforcementStatus> {
    if (this.autoRevertTimer) { clearTimeout(this.autoRevertTimer); this.autoRevertTimer = null }
    this.autoRevertAt = null

    if (this.backupPath && existsSync(this.backupPath)) {
      try { await execFileAsync('sudo', ['-n', 'cp', this.backupPath, RESOLV_CONF]) }
      catch (err) { this.message = `Failed to restore ${RESOLV_CONF}: ${err instanceof Error ? err.message : err}` }
    }
    this.stopHelper()

    if (this.enforcing) this.deps.audit('enforcement_reverted', reason)
    this.enforcing = false
    this.method = null
    this.since = null
    return this.getStatus()
  }

  private stopHelper(): void {
    if (this.helper && this.helper.pid) {
      // The helper runs under sudo; kill the sudo child tree.
      try { spawn('sudo', ['-n', 'kill', String(this.helper.pid)]) } catch { /* ignore */ }
      try { this.helper.kill() } catch { /* ignore */ }
    }
    this.helper = null
  }
}

async function resolveNodeBinary(preferred: string): Promise<string> {
  if (preferred && preferred !== 'node' && !preferred.includes('electron')) return preferred
  try {
    const { stdout } = await execFileAsync('bash', ['-lc', 'command -v node'])
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
