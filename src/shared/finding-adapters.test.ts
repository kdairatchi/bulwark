import { describe, it, expect } from 'vitest'
import {
  coerceFindingStatus,
  coerceRiskLevel,
  explainFinding,
  toWireFinding,
  type UnifiedFinding,
} from './finding'
import {
  fromCveVulnerability,
  fromMalwareThreat,
  fromNetworkEvent,
  fromPrivacySetting,
  fromRiskFinding,
  fromWireFinding,
  riskFindingToWire,
} from './finding-adapters'
import type { Finding } from './risk'
import type { MalwareThreat, PrivacySetting, CveVulnerability } from './types'
import type { NetworkEvent } from './network-guard'

describe('finding · coerce helpers', () => {
  it('maps severity and legacy status strings onto RiskLevel', () => {
    expect(coerceRiskLevel('critical')).toBe('critical')
    expect(coerceRiskLevel('likely_affected')).toBe('high')
    expect(coerceRiskLevel('potential_match')).toBe('medium')
    expect(coerceRiskLevel('safe')).toBe('safe')
  })

  it('prefers explicit status over level-as-status legacy', () => {
    expect(coerceFindingStatus('likely_affected', 'high')).toBe('likely_affected')
    expect(coerceFindingStatus(undefined, 'potential_match')).toBe('potential_match')
    expect(coerceFindingStatus(undefined, 'high')).toBe('potential_match')
  })
})

describe('finding-adapters', () => {
  it('keeps level/status split when projecting risk findings to wire', () => {
    const f: Finding = {
      id: 'finding_1',
      type: 'application_risk',
      subjectId: 'app-1',
      subjectName: 'Sketchy',
      level: 'high',
      confidence: 'moderate',
      familyStatus: 'needs_attention',
      status: 'potential_match',
      score: 55,
      evidence: ['Unknown publisher'],
      recommendedAction: 'Review the publisher.',
      createdAt: '2026-01-01T00:00:00.000Z',
    }
    const wire = riskFindingToWire(f)
    expect(wire.level).toBe('high')
    expect(wire.status).toBe('potential_match')
    expect(wire.category).toBe('risk')
    expect(wire.fixRecommendation).toMatch(/publisher/i)

    const unified = fromRiskFinding(f)
    expect(unified.type).toBe('application_risk')
    expect(explainFinding(unified).confidence).toMatch(/Moderate/i)
  })

  it('adapts malware threats', () => {
    const t: MalwareThreat = {
      id: 'm1',
      path: '/tmp/bad.exe',
      fileName: 'bad.exe',
      size: 12,
      detectionName: 'Trojan.Generic',
      severity: 'critical',
      source: 'heuristic',
      details: 'suspicious packer',
      selected: true,
    }
    const u = fromMalwareThreat(t)
    expect(u.type).toBe('malware')
    expect(u.level).toBe('critical')
    expect(u.status).toBe('likely_affected')
    expect(toWireFinding(u).category).toBe('malware')
  })

  it('adapts network block/alert but skips allow', () => {
    const blocked: NetworkEvent = {
      destination: 'evil.example',
      destinationType: 'domain',
      decision: 'block',
      reason: 'known_c2',
      category: 'c2',
      confidence: 0.95,
      matchedIndicator: 'evil.example',
      timestamp: '2026-01-01T00:00:00.000Z',
    }
    expect(fromNetworkEvent(blocked)?.level).toBe('critical')
    expect(fromNetworkEvent({ ...blocked, decision: 'allow', confidence: 0, reason: 'no_match' })).toBeNull()
  })

  it('adapts unprotected privacy settings only', () => {
    const setting: PrivacySetting = {
      id: 'telemetry',
      category: 'telemetry',
      label: 'Disable telemetry',
      description: 'Stops diagnostic uploads',
      enabled: false,
      reversible: true,
      requiresAdmin: true,
    }
    expect(fromPrivacySetting(setting)?.type).toBe('privacy')
    expect(fromPrivacySetting({ ...setting, enabled: true })).toBeNull()
  })

  it('adapts CVE rows', () => {
    const v: CveVulnerability = {
      id: 1,
      cveId: 'CVE-2024-1234',
      appName: 'curl',
      installedVersion: '7.0',
      severity: 'high',
      cvssScore: 8.1,
      fixedIn: '8.5',
      description: 'RCE in curl',
      firstDetectedAt: '2026-01-01T00:00:00.000Z',
      lastScannedAt: '2026-01-02T00:00:00.000Z',
    }
    const u = fromCveVulnerability(v)
    expect(u.type).toBe('vulnerability')
    expect(u.fixRecommendation).toMatch(/8\.5/)
  })

  it('round-trips legacy status-as-level wire findings', () => {
    const u = fromWireFinding({
      level: 'likely_affected',
      subjectName: 'CVE-1',
      reason: 'kev',
      category: 'kev',
    })
    expect(u.level).toBe('high')
    expect(u.status).toBe('likely_affected')
    expect(u.type).toBe('vulnerability')
  })

  it('explainFinding prefers evidence and fix recommendation', () => {
    const f: UnifiedFinding = {
      id: 'x',
      type: 'vulnerability',
      subjectName: 'CVE-1',
      level: 'high',
      status: 'confirmed_affected',
      category: 'kev',
      reason: 'kev_version_match',
      evidence: ['Version is in the known-affected range'],
      fixRecommendation: 'Apply vendor patch',
      createdAt: '2026-01-01T00:00:00.000Z',
    }
    const e = explainFinding(f)
    expect(e.why).toMatch(/known-affected/)
    expect(e.confidence).toMatch(/Confirmed/)
    expect(e.nextStep).toBe('Apply vendor patch')
  })
})
