export interface BetaReport {
  schemaVersion: 1
  build: {
    commitSha: string
    appVersion: string
    platform: string
    osVersion: string
    hardware: string
  }
  sample: {
    desktopTesters: number
    androidTvDevices: number
    androidTvManufacturers: number
  }
  metrics: {
    falsePositiveRate: number
    scanDurationP95Ms: number
    cpuPeakPercent: number
    rssPeakMb: number
    batteryImpactPercent?: number
    blockedLegitimateCount: number
    remediationAttempted: number
    remediationSucceeded: number
    remediationFailed: number
    enrollmentAttempted: number
    enrollmentSucceeded: number
    comprehensionPassed: number
    comprehensionTotal: number
  }
}

export function validateBetaReport(input: unknown): string[] {
  const errors: string[] = []
  if (!input || typeof input !== 'object' || Array.isArray(input)) return ['report must be an object']
  const report = input as Record<string, unknown>
  if (report.schemaVersion !== 1) errors.push('schemaVersion must be 1')

  const build = objectField(report, 'build', errors)
  for (const key of ['commitSha', 'appVersion', 'platform', 'osVersion', 'hardware']) {
    if (build && typeof build[key] !== 'string' || build && !(build[key] as string).trim()) {
      errors.push(`build.${key} must be a non-empty string`)
    }
  }

  const sample = objectField(report, 'sample', errors)
  integerAtLeast(sample, 'desktopTesters', 0, errors)
  integerAtLeast(sample, 'androidTvDevices', 0, errors)
  integerAtLeast(sample, 'androidTvManufacturers', 0, errors)

  const metrics = objectField(report, 'metrics', errors)
  boundedNumber(metrics, 'falsePositiveRate', 0, 1, errors)
  boundedNumber(metrics, 'scanDurationP95Ms', 0, Number.MAX_SAFE_INTEGER, errors)
  boundedNumber(metrics, 'cpuPeakPercent', 0, 100, errors)
  boundedNumber(metrics, 'rssPeakMb', 0, Number.MAX_SAFE_INTEGER, errors)
  boundedNumber(metrics, 'batteryImpactPercent', 0, 100, errors, true)
  for (const key of [
    'blockedLegitimateCount', 'remediationAttempted', 'remediationSucceeded',
    'remediationFailed', 'enrollmentAttempted', 'enrollmentSucceeded',
    'comprehensionPassed', 'comprehensionTotal',
  ]) integerAtLeast(metrics, key, 0, errors)

  if (metrics) {
    const attempted = metrics.remediationAttempted
    if (typeof attempted === 'number' && typeof metrics.remediationSucceeded === 'number'
      && typeof metrics.remediationFailed === 'number'
      && attempted !== metrics.remediationSucceeded + metrics.remediationFailed) {
      errors.push('metrics remediation counts must reconcile')
    }
    if (typeof metrics.enrollmentSucceeded === 'number' && typeof metrics.enrollmentAttempted === 'number'
      && metrics.enrollmentSucceeded > metrics.enrollmentAttempted) {
      errors.push('metrics.enrollmentSucceeded cannot exceed enrollmentAttempted')
    }
    if (typeof metrics.comprehensionPassed === 'number' && typeof metrics.comprehensionTotal === 'number'
      && metrics.comprehensionPassed > metrics.comprehensionTotal) {
      errors.push('metrics.comprehensionPassed cannot exceed comprehensionTotal')
    }
  }
  return errors
}

function objectField(parent: Record<string, unknown>, key: string, errors: string[]): Record<string, any> | null {
  const value = parent[key]
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(`${key} must be an object`)
    return null
  }
  return value as Record<string, any>
}

function integerAtLeast(
  object: Record<string, any> | null,
  key: string,
  minimum: number,
  errors: string[],
): void {
  const value = object?.[key]
  if (!Number.isInteger(value) || value < minimum) errors.push(`metrics/sample.${key} must be an integer >= ${minimum}`)
}

function boundedNumber(
  object: Record<string, any> | null,
  key: string,
  minimum: number,
  maximum: number,
  errors: string[],
  optional = false,
): void {
  const value = object?.[key]
  if (optional && value === undefined) return
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
    errors.push(`metrics.${key} must be a number between ${minimum} and ${maximum}`)
  }
}

