/**
 * Plain-language explain helpers for findings shown in the UI.
 * Evidence stays deterministic — these only rephrase what we already know.
 */

export type ExplainableFinding = {
  level: string
  subjectName: string
  reason: string
  category?: string | null
  fixRecommendation?: string | null
  confidence?: number | null
  evidence?: string[] | null
}

export type FindingExplanation = {
  familyLabel: 'safe' | 'needs_attention' | 'dangerous' | 'unknown'
  why: string[]
  recommended: string
  confidencePct: number | null
}

const CATEGORY_BLURB: Record<string, string> = {
  kev: 'This matches a vulnerability on CISA’s Known Exploited Vulnerabilities list — attackers are known to abuse it in the wild.',
  advisory: 'A vendor or distro security advisory says this installed version is still affected.',
  osv: 'An open-source vulnerability database lists this package version as affected.',
  nvd: 'The National Vulnerability Database has a matching CVE for this product.',
  cve: 'A published CVE is associated with this software.',
  technique: 'A living-off-the-land or attack technique pattern was detected on this device.',
  vuln_heuristic: 'A high-risk vulnerability marker was found in local files or settings.',
  publisher: 'The publisher looks unknown or untrusted compared with common vendors.',
  name: 'The application name matches patterns often used by risky or pirated software.',
  ransomware: 'This finding is associated with ransomware campaigns.',
}

function familyFromLevel(level: string): FindingExplanation['familyLabel'] {
  const l = level.toLowerCase()
  if (/dangerous|critical|likely_affected|high/.test(l)) return 'dangerous'
  if (/needs_attention|potential|medium/.test(l)) return 'needs_attention'
  if (/safe|fixed|low/.test(l)) return 'safe'
  return 'unknown'
}

function humanizeEvidenceToken(token: string): string {
  const t = token.trim()
  if (!t) return t
  if (t.startsWith('advisory:')) return `Matched advisory ${t.slice('advisory:'.length)}`
  if (t.startsWith('app:')) return `Installed as ${t.slice('app:'.length)}`
  if (t.startsWith('ref:')) return `Reference: ${t.slice('ref:'.length)}`
  if (t.startsWith('kev_')) return t.replace(/_/g, ' ')
  if (t.includes('epss=')) return `Exploit probability signal (${t})`
  return t
}

/** Explain a cloud / inventory finding for parents and end users. */
export function explainFinding(f: ExplainableFinding): FindingExplanation {
  const category = (f.category || '').trim().toLowerCase()
  const why: string[] = []

  if (category && CATEGORY_BLURB[category]) why.push(CATEGORY_BLURB[category])

  const evidence = Array.isArray(f.evidence) ? f.evidence.filter(Boolean) : []
  for (const line of evidence.slice(0, 6)) {
    const human = humanizeEvidenceToken(line)
    if (human && !why.includes(human)) why.push(human)
  }

  const reason = (f.reason || '').trim()
  if (reason && why.length < 4) {
    // Prefer a short plain reason if evidence was empty
    if (evidence.length === 0) why.push(reason.slice(0, 200))
  }

  if (why.length === 0) {
    why.push(`Bulwrk flagged ${f.subjectName || 'this item'} based on on-device checks.`)
  }

  const recommended = (f.fixRecommendation || '').trim()
    || (category === 'kev' || category === 'advisory' || category === 'osv' || category === 'nvd' || category === 'cve'
      ? `Update or remove ${f.subjectName || 'this software'}, then rescan.`
      : 'Review this finding. Quarantine or remove anything you do not trust, then rescan.')

  const confidencePct = typeof f.confidence === 'number' && Number.isFinite(f.confidence)
    ? Math.round(Math.max(0, Math.min(1, f.confidence)) * 100)
    : null

  return {
    familyLabel: familyFromLevel(f.level),
    why: why.slice(0, 8),
    recommended: recommended.slice(0, 280),
    confidencePct,
  }
}

/** Explain a local malware threat card. */
export function explainMalwareThreat(input: {
  severity: string
  source?: string
  details?: string
  detectionName?: string
  /** Threat path — used to avoid pushing quarantine for system-policy findings. */
  path?: string
  /** When false, quarantine is not the primary action. */
  selected?: boolean
}): { why: string[]; recommended: string } {
  const why: string[] = []
  const sev = (input.severity || '').toLowerCase()
  const source = (input.source || '').toLowerCase()
  const path = (input.path || '').replace(/\\/g, '/')
  const detection = (input.detectionName || '').toLowerCase()
  const isSystemPolicy =
    path === '/etc/hosts'
    || path === 'crontab'
    || path.startsWith('/etc/cron.d/')
    || path === '/etc/ld.so.preload'
    || (detection.includes('linuxpersistence') && input.selected === false)
    || detection.includes('hoststamper')
    || detection.includes('hostsredirect')

  if (sev === 'critical' || sev === 'high') {
    why.push(isSystemPolicy
      ? 'This was rated high severity — review the persistence or system-policy entry carefully.'
      : 'This was rated high severity — treat it as unsafe until you review the file.')
  } else if (sev === 'medium') {
    why.push('This may be unwanted or risky software. Confirm whether you installed it on purpose.')
  } else {
    why.push('This matched a lower-confidence rule. Still worth a quick look.')
  }

  if (source.includes('signature') || source.includes('yara')) {
    why.push('A known malware signature matched this file.')
  } else if (source.includes('heuristic')) {
    why.push('Heuristic analysis found suspicious behavior patterns (not a single known signature).')
  } else if (source.includes('defender') || source.includes('clam') || source.includes('av')) {
    why.push('A system antivirus / scanner engine also reported this file.')
  }

  if (input.details?.trim()) why.push(input.details.trim().slice(0, 220))

  let recommended: string
  if (isSystemPolicy || input.selected === false) {
    recommended = 'Review this finding manually — quarantine cannot safely change system policy files. Remove or disable the entry yourself if it is malicious.'
  } else if (sev === 'critical' || sev === 'high') {
    recommended = 'Quarantine the selected threats, then run another scan. Do not open the file.'
  } else {
    recommended = 'If you do not recognize this file, quarantine it. You can allowlist false positives later.'
  }

  return { why: why.slice(0, 6), recommended }
}

export function familyStatusLabel(status: FindingExplanation['familyLabel']): string {
  switch (status) {
    case 'safe': return 'Looks safe'
    case 'needs_attention': return 'Needs attention'
    case 'dangerous': return 'Take action'
    default: return 'Review'
  }
}
