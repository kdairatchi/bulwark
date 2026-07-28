import { describe, expect, it } from 'vitest'
import { evaluateAdvisoryVersion } from './vendor-advisories'

describe('vendor-advisories', () => {
  it('evaluates introduced and fixed bounds inclusively', () => {
    const range = { introduced: '2.0.0', fixedIn: '2.3.4' }
    expect(evaluateAdvisoryVersion('1.9.9', range)).toBe('not_affected')
    expect(evaluateAdvisoryVersion('2.0.0', range)).toBe('affected')
    expect(evaluateAdvisoryVersion('2.3.3', range)).toBe('affected')
    expect(evaluateAdvisoryVersion('2.3.4', range)).toBe('fixed')
  })

  it('supports distro revision and vulnerableBelow ranges', () => {
    expect(evaluateAdvisoryVersion('2.31-0ubuntu9.14', { vulnerableBelow: '2.31-0ubuntu9.15' }))
      .toBe('affected')
    expect(evaluateAdvisoryVersion('2.31-0ubuntu9.15', { vulnerableBelow: '2.31-0ubuntu9.15' }))
      .toBe('fixed')
  })

  it('does not guess when the advisory or installed version is incomplete', () => {
    expect(evaluateAdvisoryVersion('unknown', { fixedIn: '1.2.3' })).toBe('unknown')
    expect(evaluateAdvisoryVersion('1.2.3', {})).toBe('unknown')
  })
})

