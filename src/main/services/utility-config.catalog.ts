/**
 * Curated WinUtil-style Utility -> Config catalog.
 * IDs are stable UI/API identifiers; executable names and args are hardcoded.
 */
export type UtilityConfigFeatureKind = 'optional-feature' | 'boot' | 'scheduled-task'

export type UtilityConfigFeatureId =
  | 'netfx-all'
  | 'hyper-v'
  | 'legacy-media'
  | 'nfs'
  | 'wsl'
  | 'windows-sandbox'
  | 'telnet-client'
  | 'tftp-client'
  | 'containers'
  | 'f8-boot-recovery'
  | 'daily-registry-backup'

export type UtilityLegacyPanelId =
  | 'control-panel'
  | 'network'
  | 'power'
  | 'region'
  | 'sound'
  | 'system'
  | 'user-accounts'

export type UtilityConfigFixId =
  | 'reset-network'
  | 'reset-windows-update'
  | 'system-corruption-scan'
  | 'winget-repair'

export interface UtilityConfigFeatureDefinition {
  id: UtilityConfigFeatureId
  name: string
  description: string
  kind: UtilityConfigFeatureKind
  requiresAdmin: boolean
  featureNames?: string[]
  notes?: string
}

export interface UtilityLegacyPanelDefinition {
  id: UtilityLegacyPanelId
  name: string
  description: string
  command: 'control.exe' | 'netplwiz.exe'
  args: string[]
}

export interface UtilityConfigFixDefinition {
  id: UtilityConfigFixId
  name: string
  description: string
  requiresAdmin: boolean
  requiresReboot: boolean
  notes?: string
}

export const UTILITY_CONFIG_FEATURES: UtilityConfigFeatureDefinition[] = [
  {
    id: 'netfx-all',
    name: '.NET Framework 3.5',
    description: 'Enable .NET Framework 3.5 and related activation features when available.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['NetFx3', 'WCF-HTTP-Activation', 'WCF-NonHTTP-Activation'],
    notes: 'Windows may require installation media or Windows Update access for NetFx3 payloads.',
  },
  {
    id: 'hyper-v',
    name: 'Hyper-V',
    description: 'Enable the Hyper-V virtualization platform.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['Microsoft-Hyper-V-All'],
    notes: 'Requires supported Windows edition and hardware virtualization.',
  },
  {
    id: 'legacy-media',
    name: 'Legacy media components',
    description: 'Enable Windows Media Player and DirectPlay when available.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['WindowsMediaPlayer', 'DirectPlay'],
  },
  {
    id: 'nfs',
    name: 'NFS client',
    description: 'Enable Windows Services for NFS client components when available.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['ServicesForNFS-ClientOnly', 'ClientForNFS-Infrastructure'],
  },
  {
    id: 'wsl',
    name: 'Windows Subsystem for Linux',
    description: 'Enable WSL and the Virtual Machine Platform used by WSL 2.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform'],
    notes: 'A reboot is usually required before WSL can finish setup.',
  },
  {
    id: 'windows-sandbox',
    name: 'Windows Sandbox',
    description: 'Enable the disposable Windows Sandbox feature.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['Containers-DisposableClientVM'],
    notes: 'Requires a supported Windows edition and virtualization support.',
  },
  {
    id: 'telnet-client',
    name: 'Telnet client',
    description: 'Enable the legacy Telnet client optional feature.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['TelnetClient'],
  },
  {
    id: 'tftp-client',
    name: 'TFTP client',
    description: 'Enable the Trivial File Transfer Protocol client.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['TFTP'],
  },
  {
    id: 'containers',
    name: 'Windows Containers',
    description: 'Enable the Containers optional feature used by Windows container workloads.',
    kind: 'optional-feature',
    requiresAdmin: true,
    featureNames: ['Containers'],
    notes: 'Requires a supported Windows edition; often paired with Hyper-V.',
  },
  {
    id: 'f8-boot-recovery',
    name: 'Legacy F8 boot recovery',
    description: 'Use the legacy boot menu policy so F8 can open recovery options.',
    kind: 'boot',
    requiresAdmin: true,
    notes: 'Revert sets bootmenupolicy back to standard.',
  },
  {
    id: 'daily-registry-backup',
    name: 'Daily registry backup',
    description: 'Create a daily 12:30 AM SYSTEM task that exports core registry hives to ProgramData.',
    kind: 'scheduled-task',
    requiresAdmin: true,
    notes: 'Exports read-only .reg backups under %ProgramData%\\Bulwrk\\RegistryBackup.',
  },
]

export const UTILITY_LEGACY_PANELS: UtilityLegacyPanelDefinition[] = [
  {
    id: 'control-panel',
    name: 'Control Panel',
    description: 'Open the classic Windows Control Panel.',
    command: 'control.exe',
    args: [],
  },
  {
    id: 'network',
    name: 'Network Connections',
    description: 'Open classic network adapter settings.',
    command: 'control.exe',
    args: ['ncpa.cpl'],
  },
  {
    id: 'power',
    name: 'Power Options',
    description: 'Open classic power configuration.',
    command: 'control.exe',
    args: ['powercfg.cpl'],
  },
  {
    id: 'region',
    name: 'Region',
    description: 'Open classic region settings.',
    command: 'control.exe',
    args: ['intl.cpl'],
  },
  {
    id: 'sound',
    name: 'Sound',
    description: 'Open classic sound settings.',
    command: 'control.exe',
    args: ['mmsys.cpl'],
  },
  {
    id: 'system',
    name: 'System Properties',
    description: 'Open classic system properties.',
    command: 'control.exe',
    args: ['sysdm.cpl'],
  },
  {
    id: 'user-accounts',
    name: 'User Accounts',
    description: 'Open classic user account management.',
    command: 'control.exe',
    args: ['/name', 'Microsoft.UserAccounts'],
  },
]

export const UTILITY_CONFIG_FIXES: UtilityConfigFixDefinition[] = [
  {
    id: 'reset-network',
    name: 'Reset network stack',
    description: 'Run netsh IP and Winsock reset commands.',
    requiresAdmin: true,
    requiresReboot: true,
    notes: 'Does not change adapter settings directly; Windows usually needs a reboot afterwards.',
  },
  {
    id: 'reset-windows-update',
    name: 'Restart Windows Update services',
    description: 'Best-effort restart of Windows Update, BITS, and CryptSvc services.',
    requiresAdmin: true,
    requiresReboot: false,
    notes: 'Intentionally avoids deleting SoftwareDistribution or Catroot2 content.',
  },
  {
    id: 'system-corruption-scan',
    name: 'System corruption scan',
    description: 'Run SFC and DISM RestoreHealth using the existing Disk Repair command pattern.',
    requiresAdmin: true,
    requiresReboot: false,
    notes: 'Long-running operation; the Config tab streams SFC/DISM progress while this runs.',
  },
  {
    id: 'winget-repair',
    name: 'Repair winget sources',
    description: 'Reset and update winget sources, or return an App Installer hint if winget is missing.',
    requiresAdmin: false,
    requiresReboot: false,
  },
]

export const OPENSSH_SERVER_CAPABILITY = 'OpenSSH.Server~~~~0.0.1.0'
export const DAILY_REGISTRY_BACKUP_TASK = '\\Bulwrk\\DailyRegistryBackup'
