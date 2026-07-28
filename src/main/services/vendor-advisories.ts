/**
 * Conservative evaluator for vendor/distro advisory version ranges.
 *
 * This module deliberately does not fetch advisories. Feed adapters can map
 * their native ranges into this small shape, then share the same decision
 * boundary and unknown-version behavior.
 */

import { isVersionAtLeast } from './cve-filter'

export interface AdvisoryVersionRange {
  /** First affected version, inclusive. */
  introduced?: string
  /** First fixed version, inclusive. */
  fixedIn?: string
  /** Compatibility alias used by KEV-style feeds. */
  vulnerableBelow?: string
}

export type AdvisoryVersionStatus = 'affected' | 'fixed' | 'not_affected' | 'unknown'

export function evaluateAdvisoryVersion(
  installedVersion: string,
  range: AdvisoryVersionRange,
): AdvisoryVersionStatus {
  const installed = installedVersion.trim()
  if (!installed || /^(unknown|n\/a|-)$/i.test(installed)) return 'unknown'

  const introduced = range.introduced?.trim()
  const fixedIn = (range.fixedIn || range.vulnerableBelow)?.trim()
  if (!introduced && !fixedIn) return 'unknown'

  if (introduced && !isVersionAtLeast(installed, introduced)) return 'not_affected'
  if (fixedIn && isVersionAtLeast(installed, fixedIn)) return 'fixed'
  return 'affected'
}

