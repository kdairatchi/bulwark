/**
 * Unique Bulwrk voice for live Linux malware-scan status.
 * Deterministic — describes the current surface without inventing findings.
 */

export type LinuxScanSurface =
  | 'init'
  | 'discovering'
  | 'signatures'
  | 'heuristics'
  | 'scripts'
  | 'system'
  | 'persistence'
  | 'defender'
  | 'complete'

const SURFACE_FOCUS: Record<LinuxScanSurface, string> = {
  init: 'Engines · warming up',
  discovering: 'Filesystem · mapping drop zones',
  signatures: 'YARA · known Linux malware families',
  heuristics: 'Heuristics · disguise & shape checks',
  scripts: 'Scripts · shell & interpreter risk',
  system: 'Hosts · integrity watch',
  persistence: 'Autostart · crontab · systemd · preload',
  defender: 'ClamAV · native signature pass',
  complete: 'Pass complete',
}

/** Human folder nickname for progress path display. */
export function linuxPathFocus(path: string): string {
  const p = path.replace(/\\/g, '/')
  const home = (process.env.HOME || '').replace(/\\/g, '/')
  if (home && (p === home || p.startsWith(home + '/'))) {
    const rel = p.slice(home.length) || '/'
    if (rel === '/' || rel === '') return 'Home (shallow)'
    if (rel.startsWith('/Downloads')) return 'Downloads · common drop zone'
    if (rel.startsWith('/Desktop')) return 'Desktop · visible payloads'
    if (rel.startsWith('/Documents')) return 'Documents · document-borne risk'
    if (rel.startsWith('/.local/bin')) return '~/.local/bin · user PATH'
    if (rel.startsWith('/.config/autostart')) return 'XDG autostart · login hooks'
    if (rel.startsWith('/.config/systemd')) return 'User systemd · lingering units'
    if (rel.startsWith('/.config')) return '~/.config · app config'
    if (rel.startsWith('/.local/share')) return '~/.local/share · app data'
    return `Home${rel.split('/').slice(0, 3).join('/')}`
  }
  if (p.startsWith('/tmp')) return '/tmp · volatile staging'
  if (p.startsWith('/var/tmp')) return '/var/tmp · lingering staging'
  if (p.startsWith('/dev/shm')) return '/dev/shm · memory-backed drops'
  if (p.startsWith('/usr/local/bin')) return '/usr/local/bin · local installs'
  if (p.startsWith('/opt')) return '/opt · third-party trees'
  if (p.startsWith('/etc')) return '/etc · system policy'
  return p.length > 48 ? `${p.slice(0, 45)}…` : p
}

/** Short “what Bulwrk is doing right now” line for the scan hero. */
export function linuxEnvironmentNote(input: {
  step: LinuxScanSurface
  path?: string
  detail?: string
  clamAvailable?: boolean | null
}): string {
  const focus = SURFACE_FOCUS[input.step] || SURFACE_FOCUS.init
  const where = input.path ? linuxPathFocus(input.path) : null

  switch (input.step) {
    case 'init':
      return input.detail
        || 'Bulwrk is compiling signature rules and lining up Linux engines (YARA, heuristics, persistence, ClamAV if present).'
    case 'discovering':
      return where
        ? `Mapping scannable files in ${where} — scripts, ELF binaries, packages, and autostart entries.`
        : 'Walking high-risk Linux locations: Downloads, /tmp, ~/.local/bin, autostart, and local installs.'
    case 'signatures':
      return where
        ? `Matching ${where} against Bulwrk’s Linux YARA ruleset (known malware families & techniques).`
        : 'Matching files against Bulwrk’s Linux YARA ruleset — only published patterns, no guessing.'
    case 'heuristics':
      return 'Checking for disguise tricks (odd shapes, suspicious names outside system paths) without reading private document contents.'
    case 'scripts':
      return where
        ? `Reading script text in ${where} for download-and-execute and obfuscation patterns.`
        : 'Analyzing shell/Python/Ruby scripts for download-and-execute and obfuscation patterns.'
    case 'system':
      return 'Checking /etc/hosts for unexpected redirects that can steal logins or block updates.'
    case 'persistence':
      return input.detail
        || 'Inspecting crontab, user systemd units, XDG autostart, and ld.so.preload for stealthy relaunch.'
    case 'defender':
      if (input.clamAvailable === false) {
        return 'ClamAV is not installed on this machine — Bulwrk continues with YARA + heuristics. Install clamav for an extra native pass.'
      }
      return where
        ? `ClamAV is scanning ${where} with its local signature database.`
        : 'ClamAV is running a native signature pass on discovered files.'
    case 'complete':
      return input.detail || 'Linux malware pass finished. Review any findings below — quarantine keeps originals recoverable.'
    default:
      return focus
  }
}

export function linuxSurfaceFocus(step: LinuxScanSurface): string {
  return SURFACE_FOCUS[step] || SURFACE_FOCUS.init
}
