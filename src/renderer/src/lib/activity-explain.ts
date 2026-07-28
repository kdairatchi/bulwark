/**
 * Plain-language explainers for Activity / History detail popups.
 */

export type ActivityExplanation = {
  why: string[]
  recommended: string
  accent: string
}

type ScanLike = {
  type: string
  totalItemsFound: number
  totalItemsCleaned: number
  totalItemsSkipped: number
  totalSpaceSaved: number
  errorCount: number
  duration: number
  scheduled?: boolean
}

type CloudLike = {
  commandType: string
  success: boolean
  duration: number
  summary?: string | null
  error?: string | null
}

const TYPE_BLURB: Record<string, string> = {
  cleaner: 'Bulwrk cleaned junk and temporary files on this device.',
  registry: 'Bulwrk fixed or removed problematic Windows registry entries.',
  debloater: 'Bulwrk removed or listed unused preinstalled apps.',
  network: 'Bulwrk cleared network caches and connection leftovers.',
  drivers: 'Bulwrk reviewed installed drivers for cleanup opportunities.',
  malware: 'Bulwrk scanned for malware and suspicious files.',
  privacy: 'Bulwrk checked privacy / telemetry settings.',
  startup: 'Bulwrk reviewed programs that launch at startup.',
  services: 'Bulwrk reviewed background Windows services.',
  'software-update': 'Bulwrk checked installed software for available updates.',
  'cve-scan': 'Bulwrk checked installed software against known vulnerabilities.',
}

/** Explain a local scan/clean history entry. */
export function explainScanHistory(entry: ScanLike): ActivityExplanation {
  const why: string[] = []
  const blurb = TYPE_BLURB[entry.type]
  if (blurb) why.push(blurb)
  if (entry.scheduled) why.push('This run was started by a schedule, not manually.')

  if (entry.totalItemsCleaned > 0) {
    why.push(`Processed ${entry.totalItemsCleaned.toLocaleString()} item(s)`
      + (entry.totalSpaceSaved > 0 ? ` and recovered storage.` : '.'))
  } else if (entry.totalItemsFound > 0) {
    why.push(`Found ${entry.totalItemsFound.toLocaleString()} item(s); nothing was removed in this run.`)
  } else {
    why.push('Nothing notable was found in this run.')
  }

  if (entry.totalItemsSkipped > 0) {
    why.push(`${entry.totalItemsSkipped.toLocaleString()} item(s) were skipped (protected, in use, or excluded).`)
  }
  if (entry.errorCount > 0) {
    why.push(`${entry.errorCount} error(s) occurred — some items may need a retry or admin rights.`)
  }

  let recommended = 'No further action needed unless you want to scan again.'
  let accent = '#22c55e'
  if (entry.errorCount > 0) {
    recommended = 'Open the related tool and retry with administrator rights if needed.'
    accent = '#f87171'
  } else if (entry.type === 'malware' && entry.totalItemsFound > 0) {
    recommended = 'Review any remaining threats in Malware Scanner and quarantine what you do not trust.'
    accent = '#f59e0b'
  } else if (entry.type === 'cve-scan' && entry.totalItemsFound > 0) {
    recommended = 'Update or remove vulnerable apps, then rescan.'
    accent = '#f59e0b'
  } else if (entry.totalItemsCleaned > 0) {
    recommended = 'You are in good shape. Keep weekly scans on for ongoing protection.'
  }

  return { why: why.slice(0, 6), recommended, accent }
}

/** Explain a cloud remote-action history entry. */
export function explainCloudAction(entry: CloudLike): ActivityExplanation {
  const why: string[] = []
  const cmd = entry.commandType.replace(/_/g, ' ')

  if (entry.success) {
    why.push(`Remote command “${cmd}” completed successfully on this device.`)
  } else {
    why.push(`Remote command “${cmd}” failed on this device.`)
  }

  if (entry.summary?.trim()) why.push(entry.summary.trim().slice(0, 200))
  if (entry.error?.trim()) why.push(`Error: ${entry.error.trim().slice(0, 180)}`)
  if (entry.duration > 0) why.push(`Took ${Math.max(1, Math.round(entry.duration / 1000))}s.`)

  const recommended = entry.success
    ? (entry.commandType.includes('ISOLATE')
      ? 'Check parent controls — clear isolation when the risk has passed.'
      : 'Review findings or events in Cloud if you want more detail.')
    : 'Retry from parent controls, or check that the device is online and enrolled.'

  return {
    why: why.slice(0, 6),
    recommended,
    accent: entry.success ? '#22c55e' : '#f87171',
  }
}
