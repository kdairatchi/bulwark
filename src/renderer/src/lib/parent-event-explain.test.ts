import { describe, it, expect } from 'vitest'
import { explainParentEvent } from './parent-event-explain'

describe('parent-event-explain', () => {
  it('explains DNS blocks calmly with subject', () => {
    const e = explainParentEvent({ type: 'dns_block', subject: 'ads.example.com' })
    expect(e.title).toMatch(/DNS block/i)
    expect(e.why.some((w) => /ads\.example\.com/.test(w))).toBe(true)
    expect(e.severity).toBe('attention')
    expect(e.recommended.length).toBeGreaterThan(0)
  })

  it('maps isolation fuzzy types to critical', () => {
    const e = explainParentEvent({ type: 'DEVICE_ISOLATED', subject: 'TV' })
    expect(e.severity).toBe('critical')
    expect(e.why[0]).toMatch(/isolation/i)
  })

  it('falls back for unknown types without inventing details', () => {
    const e = explainParentEvent({ type: 'custom_widget_ping' })
    expect(e.why[0]).toMatch(/custom widget ping/i)
    expect(e.severity).toBe('info')
  })
})
