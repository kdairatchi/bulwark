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
  description: string
}

export const UTILITY_APP_CATALOG: UtilityCatalogApp[] = [
  // Browsers
  { id: 'Google.Chrome', name: 'Google Chrome', category: 'browsers', description: 'Fast Chromium browser with broad extension and sync support.' },
  { id: 'Mozilla.Firefox', name: 'Mozilla Firefox', category: 'browsers', description: 'Independent browser focused on privacy and open standards.' },
  { id: 'Brave.Brave', name: 'Brave', category: 'browsers', description: 'Chromium browser with built-in tracker and ad blocking.' },
  { id: 'Vivaldi.Vivaldi', name: 'Vivaldi', category: 'browsers', description: 'Highly customizable Chromium browser for power users.' },
  { id: 'Opera.Opera', name: 'Opera', category: 'browsers', description: 'Feature-rich browser with built-in tools and sidebar apps.' },
  { id: 'Microsoft.Edge', name: 'Microsoft Edge', category: 'browsers', description: 'Microsoft Chromium browser with Windows integration.' },
  { id: 'TorProject.TorBrowser', name: 'Tor Browser', category: 'browsers', description: 'Firefox-based browser routed through the Tor network.' },

  // Utilities
  { id: '7zip.7zip', name: '7-Zip', category: 'utilities', description: 'High-compression archive manager for ZIP, 7z, and more.' },
  { id: 'Notepad++.Notepad++', name: 'Notepad++', category: 'utilities', description: 'Lightweight multi-tab text and code editor.' },
  { id: 'voidtools.Everything', name: 'Everything', category: 'utilities', description: 'Instant filename search across local drives.' },
  { id: 'Microsoft.PowerToys', name: 'PowerToys', category: 'utilities', description: 'Microsoft power-user utilities for Windows productivity.' },
  { id: 'Microsoft.WindowsTerminal', name: 'Windows Terminal', category: 'utilities', description: 'Modern multi-tab terminal for PowerShell, CMD, and WSL.' },
  { id: 'ShareX.ShareX', name: 'ShareX', category: 'utilities', description: 'Screen capture, GIF, and upload automation toolkit.' },
  { id: 'Greenshot.Greenshot', name: 'Greenshot', category: 'utilities', description: 'Simple screenshot tool with annotation support.' },
  { id: 'WinDirStat.WinDirStat', name: 'WinDirStat', category: 'utilities', description: 'Visual disk usage analyzer for reclaiming space.' },
  { id: 'JAMSoftware.TreeSize.Free', name: 'TreeSize Free', category: 'utilities', description: 'Folder size explorer for spotting large directories.' },
  { id: 'AntibodySoftware.WizTree', name: 'WizTree', category: 'utilities', description: 'Very fast MFT-based disk space analyzer.' },
  { id: 'Rufus.Rufus', name: 'Rufus', category: 'utilities', description: 'Create bootable USB installers from ISO images.' },
  { id: 'Balena.Etcher', name: 'balenaEtcher', category: 'utilities', description: 'Flash OS images to USB drives and SD cards safely.' },
  { id: 'CrystalDewWorld.CrystalDiskInfo', name: 'CrystalDiskInfo', category: 'utilities', description: 'S.M.A.R.T. health monitor for hard drives and SSDs.' },
  { id: 'CPUID.CPU-Z', name: 'CPU-Z', category: 'utilities', description: 'Detailed CPU, motherboard, and memory identification.' },
  { id: 'RevoUninstaller.RevoUninstaller', name: 'Revo Uninstaller', category: 'utilities', description: 'Thorough uninstaller that cleans leftover files and keys.' },
  { id: 'SumatraPDF.SumatraPDF', name: 'SumatraPDF', category: 'utilities', description: 'Fast, lightweight PDF and ebook reader.' },
  { id: 'WinMerge.WinMerge', name: 'WinMerge', category: 'utilities', description: 'Visual file and folder comparison and merge tool.' },
  { id: 'LibreOffice.LibreOffice', name: 'LibreOffice', category: 'utilities', description: 'Free office suite for documents, sheets, and presentations.' },
  { id: 'Obsidian.Obsidian', name: 'Obsidian', category: 'utilities', description: 'Local-first Markdown knowledge base with linked notes.' },
  { id: 'Notion.Notion', name: 'Notion', category: 'utilities', description: 'All-in-one workspace for notes, docs, and databases.' },
  { id: 'qBittorrent.qBittorrent', name: 'qBittorrent', category: 'utilities', description: 'Open-source BitTorrent client without ads.' },
  { id: 'Valve.Steam', name: 'Steam', category: 'utilities', description: 'Valve game store and library launcher.' },

  // Media
  { id: 'VideoLAN.VLC', name: 'VLC media player', category: 'media', description: 'Plays almost any audio and video format.' },
  { id: 'OBSProject.OBSStudio', name: 'OBS Studio', category: 'media', description: 'Open live streaming and screen recording software.' },
  { id: 'GIMP.GIMP', name: 'GIMP', category: 'media', description: 'Free raster image editor and photo retoucher.' },
  { id: 'IrfanSkiljan.IrfanView', name: 'IrfanView', category: 'media', description: 'Fast image viewer with batch conversion tools.' },
  { id: 'Audacity.Audacity', name: 'Audacity', category: 'media', description: 'Open-source multitrack audio recorder and editor.' },
  { id: 'HandBrake.HandBrake', name: 'HandBrake', category: 'media', description: 'Video transcoder for converting and compressing media.' },
  { id: 'Spotify.Spotify', name: 'Spotify', category: 'media', description: 'Music and podcast streaming desktop client.' },
  { id: 'BlenderFoundation.Blender', name: 'Blender', category: 'media', description: '3D modeling, animation, and rendering suite.' },
  { id: 'Meltytech.Shotcut', name: 'Shotcut', category: 'media', description: 'Cross-platform open-source video editor.' },
  { id: 'KDE.Kdenlive', name: 'Kdenlive', category: 'media', description: 'Non-linear video editor from the KDE project.' },

  // Communication
  { id: 'Discord.Discord', name: 'Discord', category: 'communication', description: 'Voice, video, and text chat for communities and friends.' },
  { id: 'SlackTechnologies.Slack', name: 'Slack', category: 'communication', description: 'Team messaging and collaboration workspace.' },
  { id: 'Zoom.Zoom', name: 'Zoom', category: 'communication', description: 'Video meetings and webinars client.' },
  { id: 'Telegram.TelegramDesktop', name: 'Telegram', category: 'communication', description: 'Fast cloud messaging with large file support.' },
  { id: 'Mozilla.Thunderbird', name: 'Thunderbird', category: 'communication', description: 'Open-source desktop email and calendar client.' },
  { id: 'Signal.Signal', name: 'Signal', category: 'communication', description: 'End-to-end encrypted messaging and calls.' },
  { id: 'Microsoft.Teams', name: 'Microsoft Teams', category: 'communication', description: 'Microsoft chat, meetings, and workplace hub.' },
  { id: 'Element.Element', name: 'Element', category: 'communication', description: 'Secure Matrix client for decentralized chat.' },

  // Development
  { id: 'Microsoft.VisualStudioCode', name: 'Visual Studio Code', category: 'development', description: 'Extensible code editor from Microsoft.' },
  { id: 'Git.Git', name: 'Git', category: 'development', description: 'Distributed version control system.' },
  { id: 'GitHub.cli', name: 'GitHub CLI', category: 'development', description: 'Command-line interface for GitHub workflows.' },
  { id: 'GitHub.GitHubDesktop', name: 'GitHub Desktop', category: 'development', description: 'Graphical Git client tailored for GitHub.' },
  { id: 'OpenJS.NodeJS.LTS', name: 'Node.js LTS', category: 'development', description: 'Long-term support JavaScript runtime.' },
  { id: 'Python.Python.3.12', name: 'Python 3.12', category: 'development', description: 'Python 3.12 language runtime for Windows.' },
  { id: 'Microsoft.PowerShell', name: 'PowerShell', category: 'development', description: 'Cross-platform PowerShell 7 shell and scripting.' },
  { id: 'Docker.DockerDesktop', name: 'Docker Desktop', category: 'development', description: 'Local containers and Kubernetes for Windows.' },
  { id: 'Postman.Postman', name: 'Postman', category: 'development', description: 'API design, testing, and collaboration client.' },
  { id: 'WinSCP.WinSCP', name: 'WinSCP', category: 'development', description: 'SFTP, SCP, and FTP file transfer client.' },
  { id: 'PuTTY.PuTTY', name: 'PuTTY', category: 'development', description: 'Classic SSH and Telnet terminal client.' },
  { id: 'FileZilla.FileZilla', name: 'FileZilla', category: 'development', description: 'FTP and FTPS client with site manager.' },
  { id: 'DBeaver.DBeaver.Community', name: 'DBeaver Community', category: 'development', description: 'Universal SQL database management tool.' },
  { id: 'Insomnia.Insomnia', name: 'Insomnia', category: 'development', description: 'API client for REST, GraphQL, and gRPC.' },
  { id: 'JetBrains.Toolbox', name: 'JetBrains Toolbox', category: 'development', description: 'Installer and updater for JetBrains IDEs.' },
  { id: 'Neovim.Neovim', name: 'Neovim', category: 'development', description: 'Modern Vim-based terminal text editor.' },
  { id: 'Rustlang.Rustup', name: 'Rustup', category: 'development', description: 'Rust toolchain installer and version manager.' },
  { id: 'GoLang.Go', name: 'Go', category: 'development', description: 'Official Go programming language toolchain.' },

  // Security / privacy tools
  { id: 'WiresharkFoundation.Wireshark', name: 'Wireshark', category: 'security', description: 'Network protocol analyzer for packet capture.' },
  { id: 'Malwarebytes.Malwarebytes', name: 'Malwarebytes', category: 'security', description: 'Malware scanning and real-time protection.' },
  { id: 'Bitwarden.Bitwarden', name: 'Bitwarden', category: 'security', description: 'Open-source password manager with vault sync.' },
  { id: 'KeePassXCTeam.KeePassXC', name: 'KeePassXC', category: 'security', description: 'Offline KeePass-compatible password database.' },
  { id: 'Yubico.YubikeyManager', name: 'YubiKey Manager', category: 'security', description: 'Configure and manage YubiKey hardware tokens.' },
  { id: 'Proton.ProtonVPN', name: 'Proton VPN', category: 'security', description: 'VPN client from Proton with Secure Core options.' },
  { id: 'WireGuard.WireGuard', name: 'WireGuard', category: 'security', description: 'Modern high-performance VPN tunnel client.' },
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
