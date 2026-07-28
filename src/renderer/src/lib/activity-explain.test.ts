import { describe, it, expect } from 'vitest'
import { explainScanHistory, explainCloudAction } from './activity-explain'

describe('activity-explain', () => {
  it('explains a successful cleaner run', () => {
    const e = explainScanHistory({
      type: 'cleaner',
      totalItemsFound: 100,
      totalItemsCleaned: 80,
      totalItemsSkipped: 5,
      totalSpaceSaved: 1024,
      errorCount: 0,
      duration: 1200,
    })
    expect(e.why.some((w) => /junk|temporary/i.test(w))).toBe(true)
    expect(e.recommended).toMatch(/weekly|good shape/i)
  })

  it('flags malware findings for review', () => {
    const e = explainScanHistory({
      type: 'malware',
      totalItemsFound: 2,
      totalItemsCleaned: 0,
      totalItemsSkipped: 0,
      totalSpaceSaved: 0,
      errorCount: 0,
      duration: 500,
    })
    expect(e.recommended).toMatch(/quarantine|Malware/i)
  })

  it('explains failed cloud actions', () => {
    const e = explainCloudAction({
      commandType: 'RUN_MALWARE_SCAN',
      success: false,
      duration: 100,
      error: 'device offline',
    })
    expect(e.accent).toBe('#f87171')
    expect(e.recommended).toMatch(/Retry|online/i)
  })
})
