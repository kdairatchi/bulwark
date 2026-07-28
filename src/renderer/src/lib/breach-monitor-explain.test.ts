import { describe, it, expect } from 'vitest'
import { explainBreachMonitorSetup } from './breach-monitor-explain'

describe('breach-monitor-explain', () => {
  it('explains breach monitoring without claiming mailbox access', () => {
    const e = explainBreachMonitorSetup()
    expect(e.why.length).toBeGreaterThan(0)
    expect(e.whatHappens.length).toBeGreaterThan(0)
    expect(e.privacy.join(' ')).toMatch(/not your mailbox/i)
    expect(e.recommended).toMatch(/password/i)
  })
})
