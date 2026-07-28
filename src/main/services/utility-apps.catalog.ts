/**
 * Curated WinGet catalog for Utility → Install.
 * IDs must match winget package IDs (Publisher.Name).
 */
export type UtilityAppCategory =
  | 'browsers'
  | 'utilities'
  | 'media'
  | 'communication'
  | 'development'
  | 'security'

export interface UtilityCatalogApp {
  id: string
  name: string
  category: UtilityAppCategory
  description?: string
}

export const UTILITY_APP_CATALOG: UtilityCatalogApp[] = [
  // Browsers
  { id: 'Google.Chrome', name: 'Google Chrome', category: 'browsers' },
  { id: 'Mozilla.Firefox', name: 'Mozilla Firefox', category: 'browsers' },
  { id: 'Brave.Brave', name: 'Brave', category: 'browsers' },
  { id: 'Vivaldi.Vivaldi', name: 'Vivaldi', category: 'browsers' },
  { id: 'Opera.Opera', name: 'Opera', category: 'browsers' },
  { id: 'Microsoft.Edge', name: 'Microsoft Edge', category: 'browsers' },

  // Utilities
  { id: '7zip.7zip', name: '7-Zip', category: 'utilities' },
  { id: 'Notepad++.Notepad++', name: 'Notepad++', category: 'utilities' },
  { id: 'voidtools.Everything', name: 'Everything', category: 'utilities' },
  { id: 'Microsoft.PowerToys', name: 'PowerToys', category: 'utilities' },
  { id: 'Microsoft.WindowsTerminal', name: 'Windows Terminal', category: 'utilities' },
  { id: 'ShareX.ShareX', name: 'ShareX', category: 'utilities' },
  { id: 'Greenshot.Greenshot', name: 'Greenshot', category: 'utilities' },
  { id: 'WinDirStat.WinDirStat', name: 'WinDirStat', category: 'utilities' },
  { id: 'JAMSoftware.TreeSize.Free', name: 'TreeSize Free', category: 'utilities' },
  { id: 'AntibodySoftware.WizTree', name: 'WizTree', category: 'utilities' },
  { id: 'Rufus.Rufus', name: 'Rufus', category: 'utilities' },
  { id: 'Balena.Etcher', name: 'balenaEtcher', category: 'utilities' },
  { id: 'CrystalDewWorld.CrystalDiskInfo', name: 'CrystalDiskInfo', category: 'utilities' },
  { id: 'CPUID.CPU-Z', name: 'CPU-Z', category: 'utilities' },
  { id: 'RevoUninstaller.RevoUninstaller', name: 'Revo Uninstaller', category: 'utilities' },
  { id: 'SumatraPDF.SumatraPDF', name: 'SumatraPDF', category: 'utilities' },
  { id: 'WinMerge.WinMerge', name: 'WinMerge', category: 'utilities' },
  { id: 'LibreOffice.LibreOffice', name: 'LibreOffice', category: 'utilities' },

  // Media
  { id: 'VideoLAN.VLC', name: 'VLC media player', category: 'media' },
  { id: 'OBSProject.OBSStudio', name: 'OBS Studio', category: 'media' },
  { id: 'GIMP.GIMP', name: 'GIMP', category: 'media' },
  { id: 'IrfanSkiljan.IrfanView', name: 'IrfanView', category: 'media' },
  { id: 'Audacity.Audacity', name: 'Audacity', category: 'media' },
  { id: 'HandBrake.HandBrake', name: 'HandBrake', category: 'media' },
  { id: 'Spotify.Spotify', name: 'Spotify', category: 'media' },
  { id: 'BlenderFoundation.Blender', name: 'Blender', category: 'media' },

  // Communication
  { id: 'Discord.Discord', name: 'Discord', category: 'communication' },
  { id: 'SlackTechnologies.Slack', name: 'Slack', category: 'communication' },
  { id: 'Zoom.Zoom', name: 'Zoom', category: 'communication' },
  { id: 'Telegram.TelegramDesktop', name: 'Telegram', category: 'communication' },
  { id: 'Mozilla.Thunderbird', name: 'Thunderbird', category: 'communication' },
  { id: 'Signal.Signal', name: 'Signal', category: 'communication' },
  { id: 'Microsoft.Teams', name: 'Microsoft Teams', category: 'communication' },

  // Development
  { id: 'Microsoft.VisualStudioCode', name: 'Visual Studio Code', category: 'development' },
  { id: 'Git.Git', name: 'Git', category: 'development' },
  { id: 'GitHub.cli', name: 'GitHub CLI', category: 'development' },
  { id: 'GitHub.GitHubDesktop', name: 'GitHub Desktop', category: 'development' },
  { id: 'OpenJS.NodeJS.LTS', name: 'Node.js LTS', category: 'development' },
  { id: 'Python.Python.3.12', name: 'Python 3.12', category: 'development' },
  { id: 'Microsoft.PowerShell', name: 'PowerShell', category: 'development' },
  { id: 'Docker.DockerDesktop', name: 'Docker Desktop', category: 'development' },
  { id: 'Postman.Postman', name: 'Postman', category: 'development' },
  { id: 'WinSCP.WinSCP', name: 'WinSCP', category: 'development' },
  { id: 'PuTTY.PuTTY', name: 'PuTTY', category: 'development' },
  { id: 'FileZilla.FileZilla', name: 'FileZilla', category: 'development' },
  { id: 'DBeaver.DBeaver.Community', name: 'DBeaver Community', category: 'development' },
  { id: 'Insomnia.Insomnia', name: 'Insomnia', category: 'development' },
  { id: 'JetBrains.Toolbox', name: 'JetBrains Toolbox', category: 'development' },

  // Security / privacy tools
  { id: 'WiresharkFoundation.Wireshark', name: 'Wireshark', category: 'security' },
  { id: 'Malwarebytes.Malwarebytes', name: 'Malwarebytes', category: 'security' },
  { id: 'Bitwarden.Bitwarden', name: 'Bitwarden', category: 'security' },
  { id: 'KeePassXCTeam.KeePassXC', name: 'KeePassXC', category: 'security' },
  { id: 'Yubico.YubikeyManager', name: 'YubiKey Manager', category: 'security' },
]

export const UTILITY_CATEGORY_ORDER: UtilityAppCategory[] = [
  'browsers',
  'utilities',
  'media',
  'communication',
  'development',
  'security',
]

const UTILITY_APP_CATALOG_PACKAGE_IDS = new Set(UTILITY_APP_CATALOG.map((app) => app.id))

export function isUtilityCatalogPackageId(id: string): boolean {
  return UTILITY_APP_CATALOG_PACKAGE_IDS.has(id)
}
