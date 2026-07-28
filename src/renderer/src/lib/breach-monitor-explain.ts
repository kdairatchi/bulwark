/**
 * Calm copy for parent email breach-monitor setup.
 * Does not invent HIBP behavior — describes monitoring + review flow.
 */

export type BreachMonitorExplanation = {
  why: string[]
  whatHappens: string[]
  privacy: string[]
  recommended: string
}

/** Explain adding an email to parent breach monitoring. */
export function explainBreachMonitorSetup(): BreachMonitorExplanation {
  return {
    why: [
      'Breach monitors watch an email address for known public data breaches so you can react early.',
      'Useful for family accounts, shared streaming logins, and anything tied to a household inbox.',
      'Hits are reviewable — you mark breaches as reviewed after you change passwords or retire the account.',
    ],
    whatHappens: [
      'Bulwrk checks the address against the configured breach data source (live HIBP when keyed, otherwise stub/fixture mode).',
      'Open breaches appear under the monitored email until you mark them reviewed.',
      'You can refresh checks later or remove a monitor anytime.',
    ],
    privacy: [
      'Only the email you enter is submitted for breach lookup — not your mailbox contents.',
      'There is a per-account monitor limit; remove unused addresses to free slots.',
      'Stub mode (no API key) only returns fixture hits for labeled test addresses — not real exposure data.',
    ],
    recommended:
      'Add one household email first, review any open breaches, then rotate passwords on affected sites.',
  }
}
