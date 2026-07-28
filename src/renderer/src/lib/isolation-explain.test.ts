import { describe, it, expect } from 'vitest'
import { explainIsolation, explainClearIsolation } from './isolation-explain'

describe('isolation-explain', () => {
  it('explains isolate calmly with device name', () => {
    const e = explainIsolation('Living Room TV')
    expect(e.why[0]).toMatch(/Living Room TV/)
    expect(e.stillWorks.length).toBeGreaterThan(0)
    expect(e.blocked.length).toBeGreaterThan(0)
    expect(e.recommended).toMatch(/Clear isolation/i)
  })

  it('explains clear isolation', () => {
    const e = explainClearIsolation('Laptop')
    expect(e.why.some((w) => /Laptop/.test(w))).toBe(true)
    expect(e.recommended).toMatch(/scan/i)
  })
})
