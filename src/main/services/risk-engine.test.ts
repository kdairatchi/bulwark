import { describe, it, expect } from 'vitest'
import {
  assessRisk,
  buildAppRiskReport,
  RISK_SIGNALS,
  riskInputFromInstalledProgram,
  toFinding,
  levelLabel,
  confidenceLabel,
} from './risk-engine'
import type { RiskInput } from '../../shared/risk'
import type { InstalledProgram } from '../../shared/types'

function program(overrides: Partial<InstalledProgram> = {}): InstalledProgram {
  return {
    id: 'app-1',
    displayName: 'Example App',
    publisher: '',
    displayVersion: '1.0.0',
    installDate: '',
    estimatedSize: 0,
    installLocation: '',
    uninstallString: '',
    quietUninstallString: '',
    displayIcon: '',
    registryKey: '',
    isSystemComponent: false,
    isWindowsInstaller: false,
    lastUsed: 0,
    ...overrides,
  }
}

describe('risk-engine · assessRisk scoring', () => {
  it('returns safe with no evidence and reports it honestly', () => {
    const r = assessRisk({})
    expect(r.score).toBe(0)
    expect(r.level).toBe('safe')
    expect(r.confidence).toBe('weak')
    expect(r.familyStatus).toBe('unknown')
    expect(r.signals).toHaveLength(0)
    expect(r.explanation[0]).toMatch(/not enough information/i)
    expect(r.recommendedAction).toBe('No action needed.')
  })

  it('sums positive weights and clamps at 100', () => {
    const input: RiskInput = {
      unsignedExecutable: true, // 25
      unknownPublisher: true, // 20
      requestsAdmin: true, // 20
      maliciousNetworkIndicator: true, // 25
      persistenceMechanism: true, // 20
      runsAtStartup: true, // 15
    }
    const r = assessRisk(input)
    // 125 raw → clamped to 100
    expect(r.score).toBe(100)
    expect(r.level).toBe('critical')
  })

  it('applies negative weights and clamps at 0', () => {
    const r = assessRisk({
      signedByTrustedPublisher: true, // -20
      trustedPackageManager: true, // -15
      highPrevalence: true, // -10
    })
    expect(r.score).toBe(0)
    expect(r.level).toBe('safe')
    expect(r.familyStatus).toBe('safe') // signals fired, so not "unknown"
  })

  it('nets positive and negative signals', () => {
    // unsigned(+25) + startup(+15) + trusted pkg mgr(-15) = 25 → medium
    const r = assessRisk({
      unsignedExecutable: true,
      runsAtStartup: true,
      trustedPackageManager: true,
    })
    expect(r.score).toBe(25)
    expect(r.level).toBe('medium')
  })

  it.each([
    [{}, 'safe'],
    [{ runsAtStartup: true }, 'low'], // 15
    [{ unsignedExecutable: true }, 'medium'], // 25
    [{ unsignedExecutable: true, unknownPublisher: true, runsAtStartup: true }, 'high'], // 60
    [{ unsignedExecutable: true, unknownPublisher: true, requestsAdmin: true, maliciousNetworkIndicator: true }, 'critical'], // 90
  ] as [RiskInput, string][])('maps score to level %#', (input, expectedLevel) => {
    expect(assessRisk(input).level).toBe(expectedLevel)
  })

  it('floors a malicious-network match to at least high, overriding trust signals', () => {
    // trusted(-20) + pkg mgr(-15) + malicious(+25) = -10 → would clamp to safe,
    // but the malicious-network floor forces at least high.
    const r = assessRisk({ signedByTrustedPublisher: true, trustedPackageManager: true, maliciousNetworkIndicator: true })
    expect(r.score).toBeGreaterThanOrEqual(50)
    expect(r.level).toBe('high')
  })

  it('orders signals by absolute weight, most impactful first', () => {
    const r = assessRisk({ runsAtStartup: true, unsignedExecutable: true, recentlyCreatedBinary: true })
    expect(r.signals.map((s) => s.id)).toEqual([
      'unsigned_executable', // 25
      'runs_at_startup', // 15
      'recently_created_binary', // 10
    ])
  })
})

describe('risk-engine · confidence', () => {
  it('is strong when a malicious network indicator matches, even alone', () => {
    expect(assessRisk({ maliciousNetworkIndicator: true }).confidence).toBe('strong')
  })

  it('is strong with three or more corroborating signals', () => {
    expect(
      assessRisk({ unsignedExecutable: true, unknownPublisher: true, runsAtStartup: true }).confidence,
    ).toBe('strong')
  })

  it('is moderate with one or two signals', () => {
    expect(assessRisk({ unknownPublisher: true }).confidence).toBe('moderate')
    expect(assessRisk({ unknownPublisher: true, runsAtStartup: true }).confidence).toBe('moderate')
  })

  it('is weak with no signals', () => {
    expect(assessRisk({}).confidence).toBe('weak')
  })
})

describe('risk-engine · family status', () => {
  it('is unknown only when nothing is known', () => {
    expect(assessRisk({}).familyStatus).toBe('unknown')
  })

  it('maps medium risk to needs_attention', () => {
    expect(assessRisk({ unsignedExecutable: true }).familyStatus).toBe('needs_attention')
  })

  it('maps high/critical risk to dangerous', () => {
    expect(
      assessRisk({ unsignedExecutable: true, unknownPublisher: true, requestsAdmin: true }).familyStatus,
    ).toBe('dangerous')
  })
})

describe('risk-engine · recommended action', () => {
  it('prioritizes the malicious network response', () => {
    const r = assessRisk({ maliciousNetworkIndicator: true, unsignedExecutable: true })
    expect(r.recommendedAction).toBe('Block network access and quarantine the file.')
  })

  it('recommends quarantine for high risk without network indicators', () => {
    const r = assessRisk({ unsignedExecutable: true, unknownPublisher: true, requestsAdmin: true })
    expect(r.recommendedAction).toMatch(/quarantine/i)
  })
})

describe('risk-engine · explanation (deterministic, template-based)', () => {
  it('lists one plain-language line per fired signal, in impact order', () => {
    const r = assessRisk({ unsignedExecutable: true, runsAtStartup: true })
    expect(r.explanation).toEqual([
      RISK_SIGNALS.unsigned_executable.evidence,
      RISK_SIGNALS.runs_at_startup.evidence,
    ])
  })

  it('is stable across repeated calls (no randomness)', () => {
    const input: RiskInput = { unsignedExecutable: true, unknownPublisher: true, requestsAdmin: true }
    expect(assessRisk(input)).toEqual(assessRisk(input))
  })
})

describe('risk-engine · installed-program adapter', () => {
  it('flags an empty publisher as unknown', () => {
    const input = riskInputFromInstalledProgram(program({ publisher: '' }))
    expect(input.unknownPublisher).toBe(true)
    expect(input.signedByTrustedPublisher).toBe(false)
  })

  it('recognizes a trusted publisher (case-insensitive)', () => {
    const input = riskInputFromInstalledProgram(program({ publisher: 'Microsoft Corporation' }))
    expect(input.signedByTrustedPublisher).toBe(true)
    expect(input.unknownPublisher).toBe(false)
  })

  it('treats Windows Installer packages as a trusted package manager', () => {
    const input = riskInputFromInstalledProgram(program({ isWindowsInstaller: true }))
    expect(input.trustedPackageManager).toBe(true)
  })

  it('detects executables in a temp directory', () => {
    expect(
      riskInputFromInstalledProgram(program({ installLocation: 'C:\\Users\\me\\AppData\\Local\\Temp\\x' }))
        .tempDirectoryBinary,
    ).toBe(true)
    expect(
      riskInputFromInstalledProgram(program({ installLocation: '/tmp/installer' })).tempDirectoryBinary,
    ).toBe(true)
    expect(
      riskInputFromInstalledProgram(program({ installLocation: 'C:\\Program Files\\App' }))
        .tempDirectoryBinary,
    ).toBe(false)
  })

  it('flags a recently created binary using injectable now', () => {
    const now = Date.parse('2026-01-10T00:00:00Z')
    const recent = riskInputFromInstalledProgram(program({ installDate: '2026-01-08' }), now)
    const old = riskInputFromInstalledProgram(program({ installDate: '2025-01-08' }), now)
    expect(recent.recentlyCreatedBinary).toBe(true)
    expect(old.recentlyCreatedBinary).toBe(false)
  })

  it('produces a low-risk assessment for a well-known, package-managed app', () => {
    const input = riskInputFromInstalledProgram(
      program({ publisher: 'Google LLC', isWindowsInstaller: true, installLocation: 'C:\\Program Files\\Chrome' }),
    )
    const r = assessRisk(input)
    expect(r.level).toBe('safe')
    expect(r.familyStatus).toBe('safe')
  })

  it('raises risk for an unknown-publisher app installed in temp', () => {
    const input = riskInputFromInstalledProgram(
      program({ publisher: '', installLocation: 'C:\\Temp\\sketchy' }),
    )
    const r = assessRisk(input)
    // unknownPublisher(20) + tempDirectoryBinary(10) = 30 → medium
    expect(r.score).toBe(30)
    expect(r.level).toBe('medium')
  })
})

describe('risk-engine · toFinding', () => {
  it('builds a structured finding with fixed timestamp', () => {
    const assessment = assessRisk({ unsignedExecutable: true, unknownPublisher: true, requestsAdmin: true })
    const finding = toFinding('app-42', 'Sketchy Player', assessment, '2026-07-27T18:30:00Z')
    expect(finding).toMatchObject({
      id: 'finding_app-42',
      type: 'application_risk',
      subjectId: 'app-42',
      subjectName: 'Sketchy Player',
      level: assessment.level,
      confidence: assessment.confidence,
      status: 'potential_match',
      createdAt: '2026-07-27T18:30:00Z',
    })
    expect(finding.evidence).toEqual(assessment.explanation)
  })

  it('marks a finding unknown when nothing is known', () => {
    const finding = toFinding('app-0', 'Mystery', assessRisk({}))
    expect(finding.status).toBe('unknown')
    expect(finding.familyStatus).toBe('unknown')
  })
})

describe('risk-engine · buildAppRiskReport', () => {
  const now = Date.parse('2026-07-27T00:00:00Z')

  it('returns an empty report with perfect posture for no programs', () => {
    const report = buildAppRiskReport([], now)
    expect(report.total).toBe(0)
    expect(report.postureScore).toBe(100)
    expect(report.findings).toEqual([])
  })

  it('escalates a subject with a confirmed malicious-network indicator', () => {
    const programs = [
      program({ id: 'clean', displayName: 'Clean', publisher: 'Microsoft Corporation', isWindowsInstaller: true }),
      program({ id: 'beacon', displayName: 'Beacon', publisher: 'Microsoft Corporation', isWindowsInstaller: true }),
    ]
    const report = buildAppRiskReport(programs, now, { maliciousSubjectIds: new Set(['beacon']) })
    const beacon = report.findings.find((f) => f.subjectId === 'beacon')!
    const clean = report.findings.find((f) => f.subjectId === 'clean')!
    // The malicious-network signal is decisive: even a trusted, package-managed app
    // is floored to "high"/dangerous with strong confidence when it contacts C2.
    expect(beacon.level).toBe('high')
    expect(beacon.confidence).toBe('strong')
    expect(beacon.familyStatus).toBe('dangerous')
    expect(beacon.evidence.some((e) => /malicious/i.test(e))).toBe(true)
    expect(clean.level).toBe('safe')
    expect(report.familySummary.dangerous).toBe(1)
  })

  it('aggregates counts, sorts worst-first, and scores posture', () => {
    const programs = [
      program({ id: 'a', displayName: 'Trusted', publisher: 'Microsoft Corporation', isWindowsInstaller: true }),
      program({ id: 'b', displayName: 'Unknown Pub', publisher: '' }),
      program({ id: 'c', displayName: 'Temp Sketch', publisher: '', installLocation: 'C:\\Temp\\x' }),
    ]
    const report = buildAppRiskReport(programs, now)

    expect(report.total).toBe(3)
    // 'c' (unknown+temp = 30, medium) should sort ahead of 'b' (20, low) and 'a' (safe)
    expect(report.findings[0].subjectId).toBe('c')
    expect(report.findings[0].level).toBe('medium')
    expect(report.summary.medium).toBe(1)
    expect(report.summary.low).toBe(1)
    expect(report.summary.safe).toBe(1)
    // one needs_attention (medium) out of three → 100*(1 - 0.5/3) ≈ 83
    expect(report.familySummary.needs_attention).toBe(1)
    expect(report.postureScore).toBe(83)
    expect(report.generatedAt).toBe('2026-07-27T00:00:00.000Z')
  })
})

describe('risk-engine · labels', () => {
  it('exposes human-readable level and confidence labels', () => {
    expect(levelLabel('high')).toBe('High risk')
    expect(confidenceLabel('strong')).toBe('Strong')
  })
})
