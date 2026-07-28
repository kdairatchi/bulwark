/**
 * Deterministic breakdown for the Dashboard health score ring.
 * Mirrors DashboardPage scoring so the UI can explain “why this score”.
 */

export type HealthScoreFactor = {
  id: string
  label: string
  detail: string
  impact: 'positive' | 'negative' | 'neutral'
}

export type HealthScoreExplanation = {
  score: number
  why: string[]
  recommended: string
  factors: HealthScoreFactor[]
}

export function explainHealthScore(input: {
  toolsTotal: number
  toolsRecent: number
  missingToolLabels: string[]
  worstDiskUsage: number | null
  daysSinceScan: number | null
  hasLastScan: boolean
}): HealthScoreExplanation {
  const totalTools = Math.max(1, input.toolsTotal)
  const doneTools = Math.max(0, Math.min(totalTools, input.toolsRecent))
  let score = Math.round((doneTools / totalTools) * 60)

  const factors: HealthScoreFactor[] = [
    {
      id: 'coverage',
      label: 'Tool coverage',
      detail: `${doneTools}/${totalTools} protection tools used in the last 2 weeks (up to 60 pts).`,
      impact: doneTools === totalTools ? 'positive' : doneTools === 0 ? 'negative' : 'neutral',
    },
  ]

  let diskPenalty = 0
  if (input.worstDiskUsage != null && input.worstDiskUsage > 0.7) {
    diskPenalty = Math.min(20, Math.round(((input.worstDiskUsage - 0.7) / 0.3) * 20))
    score -= diskPenalty
    factors.push({
      id: 'disk',
      label: 'Disk pressure',
      detail: `A drive is ${Math.round(input.worstDiskUsage * 100)}% full (−${diskPenalty} pts).`,
      impact: 'negative',
    })
  } else {
    factors.push({
      id: 'disk',
      label: 'Disk pressure',
      detail: 'No drive is critically full.',
      impact: 'positive',
    })
  }

  let freshnessPenalty = 0
  if (input.hasLastScan && input.daysSinceScan != null) {
    freshnessPenalty = Math.min(20, Math.round(input.daysSinceScan * (20 / 7)))
    score -= freshnessPenalty
    factors.push({
      id: 'freshness',
      label: 'Scan freshness',
      detail: freshnessPenalty > 0
        ? `Last scan was ~${Math.round(input.daysSinceScan)} day(s) ago (−${freshnessPenalty} pts).`
        : 'Last scan was recent.',
      impact: freshnessPenalty > 0 ? 'negative' : 'positive',
    })
    score += 40
    factors.push({
      id: 'baseline',
      label: 'Scan baseline',
      detail: 'You have completed at least one scan (+40 pts).',
      impact: 'positive',
    })
  } else {
    score -= 10
    factors.push({
      id: 'freshness',
      label: 'Scan freshness',
      detail: 'No scan on record yet (−10 pts).',
      impact: 'negative',
    })
  }

  score = Math.max(0, Math.min(100, score))

  const why = factors.map((f) => f.detail)
  let recommended = 'Keep running weekly scans to hold a strong health score.'
  if (!input.hasLastScan) {
    recommended = 'Run a malware scan or Quick Clean to establish a baseline.'
  } else if (input.missingToolLabels.length > 0) {
    recommended = `Try ${input.missingToolLabels.slice(0, 2).join(' and ')} next — unused tools lower coverage.`
  } else if (diskPenalty > 0) {
    recommended = 'Free disk space on the fullest drive, then rescan.'
  } else if (freshnessPenalty >= 10) {
    recommended = 'Run a fresh scan — older results lower this score.'
  }

  return { score, why: why.slice(0, 8), recommended, factors }
}
