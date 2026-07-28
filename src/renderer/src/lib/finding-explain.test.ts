import { describe, it, expect } from 'vitest'
import {
  explainFinding,
  explainMalwareThreat,
  familyStatusLabel,
} from './finding-explain'

describe('finding-explain', () => {
  it('explains KEV findings with category blurb and fix text', () => {
    const e = explainFinding({
      level: 'likely_affected',
      subjectName: 'CVE-2023-38545',
      reason: 'kev_version_match_<8.4.0:curl@7.88.1',
      category: 'kev',
      fixRecommendation: 'Upgrade curl to 8.4.0 or newer',
      confidence: 0.95,
      evidence: ['kev_version_match_<8.4.0:curl@7.88.1'],
    })
    expect(e.familyLabel).toBe('dangerous')
    expect(e.confidencePct).toBe(95)
    expect(e.why.some((w) => /Known Exploited/i.test(w))).toBe(true)
    expect(e.recommended).toMatch(/8\.4\.0/)
    expect(familyStatusLabel(e.familyLabel)).toBe('Take action')
  })

  it('falls back when evidence is empty', () => {
    const e = explainFinding({
      level: 'potential_match',
      subjectName: 'MysteryApp',
      reason: 'unknown_publisher',
      category: 'publisher',
    })
    expect(e.familyLabel).toBe('needs_attention')
    expect(e.why.length).toBeGreaterThan(0)
    expect(e.recommended).toMatch(/Review|rescan/i)
  })

  it('explains malware threats with quarantine guidance', () => {
    const e = explainMalwareThreat({
      severity: 'critical',
      source: 'signature',
      details: 'Matched trojan.generic',
      detectionName: 'Trojan.Generic',
      path: '/tmp/evil',
      selected: true,
    })
    expect(e.why.some((w) => /signature/i.test(w))).toBe(true)
    expect(e.recommended).toMatch(/Quarantine/i)
  })

  it('recommends manual review for system-policy findings', () => {
    const e = explainMalwareThreat({
      severity: 'high',
      source: 'heuristic',
      details: 'crontab downloads and pipes to shell',
      detectionName: 'Heuristic.Suspicious.LinuxPersistence',
      path: 'crontab',
      selected: false,
    })
    expect(e.recommended).toMatch(/manually/i)
    expect(e.recommended).not.toMatch(/^Quarantine the selected/)
  })

  it('treats /etc/cron.daily paths as system policy', () => {
    const e = explainMalwareThreat({
      severity: 'high',
      source: 'heuristic',
      path: '/etc/cron.daily/evil',
      selected: false,
    })
    expect(e.recommended).toMatch(/manually/i)
  })
})
