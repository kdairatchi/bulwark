// Types for system-wide DNS enforcement — pointing the OS resolver at the local
// Secure DNS resolver so filtering + DNS-over-TLS apply to every application,
// not just apps configured to use it. This is a PRIVILEGED action (needs
// elevation) and is always reversible.

export type EnforcementMethod = 'resolv.conf' | 'networksetup' | 'netsh'

export interface EnforcementStep {
  /** Human-readable description of what this step does. */
  describe: string
  /** The command that would run (for transparency in the UI/audit). */
  command: string
}

export interface EnforcementPlan {
  platform: NodeJS.Platform
  method: EnforcementMethod
  requiresElevation: boolean
  apply: EnforcementStep[]
  revert: EnforcementStep[]
}

export interface EnforcementStatus {
  enforcing: boolean
  method: EnforcementMethod | null
  /** ISO timestamp when enforcement was applied. */
  since: string | null
  /** ISO timestamp when auto-revert will fire (safety), if enforcing. */
  autoRevertAt: string | null
  /** Non-fatal note/warning for the UI (e.g. elevation unavailable). */
  message: string | null
}
