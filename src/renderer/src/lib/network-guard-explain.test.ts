import { describe, it, expect } from 'vitest'
import { explainSecureDnsEnable } from './network-guard-explain'

describe('network-guard-explain', () => {
  it('explains Secure DNS enable without claiming packet inspection', () => {
    const e = explainSecureDnsEnable()
    expect(e.why.length).toBeGreaterThan(0)
    expect(e.whatHappens.length).toBeGreaterThan(0)
    expect(e.stillWorks.length).toBeGreaterThan(0)
    expect(e.enforcementNotes.length).toBeGreaterThan(0)
    expect(e.why.join(' ')).toMatch(/metadata/i)
    expect(e.why.join(' ')).not.toMatch(/packet content|read your traffic/i)
    expect(e.recommended).toMatch(/Start the local resolver/i)
  })
})
