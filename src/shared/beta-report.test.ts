import { describe, expect, it } from 'vitest'
import { validateBetaReport, type BetaReport } from './beta-report'

const report: BetaReport = {
  schemaVersion: 1,
  build: { commitSha: 'abc123', appVersion: '1.0.0', platform: 'win32', osVersion: '11', hardware: 'test-pc' },
  sample: { desktopTesters: 20, androidTvDevices: 5, androidTvManufacturers: 2 },
  metrics: {
    falsePositiveRate: 0.04, scanDurationP95Ms: 30_000, cpuPeakPercent: 22, rssPeakMb: 350,
    blockedLegitimateCount: 0, remediationAttempted: 5, remediationSucceeded: 4, remediationFailed: 1,
    enrollmentAttempted: 20, enrollmentSucceeded: 19, comprehensionPassed: 18, comprehensionTotal: 20,
  },
}

describe('beta-report', () => {
  it('accepts a complete reconciled report', () => {
    expect(validateBetaReport(report)).toEqual([])
  })

  it('rejects missing, out-of-range, and unreconciled evidence', () => {
    const errors = validateBetaReport({
      ...report,
      metrics: { ...report.metrics, falsePositiveRate: 2, remediationFailed: 2, enrollmentSucceeded: 21 },
    })
    expect(errors).toEqual(expect.arrayContaining([
      'metrics.falsePositiveRate must be a number between 0 and 1',
      'metrics remediation counts must reconcile',
      'metrics.enrollmentSucceeded cannot exceed enrollmentAttempted',
    ]))
  })
})

