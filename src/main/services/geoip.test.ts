import { describe, it, expect } from 'vitest'
import { parseGeoipCsv, lookupCountryIn } from './geoip'

const CSV = [
  '1.0.0.0,1.0.0.255,AU',
  '1.0.1.0,1.0.3.255,CN',
  '8.8.8.0,8.8.8.255,US',
  '203.0.113.0,203.0.113.255,DE',
  'bad,line',
  '10.0.0.0,10.0.0.255,ZZ9', // invalid country → skipped
].join('\n')

describe('geoip · parseGeoipCsv', () => {
  it('parses valid rows and skips malformed ones', () => {
    const ranges = parseGeoipCsv(CSV)
    expect(ranges.cc).toEqual(['AU', 'CN', 'US', 'DE'])
    expect(ranges.starts.length).toBe(4)
    expect(ranges.ends.length).toBe(4)
  })
})

describe('geoip · lookupCountryIn', () => {
  const ranges = parseGeoipCsv(CSV)

  it('resolves IPs to the correct country via binary search', () => {
    expect(lookupCountryIn(ranges, '1.0.0.100')).toBe('AU')
    expect(lookupCountryIn(ranges, '1.0.2.5')).toBe('CN')
    expect(lookupCountryIn(ranges, '8.8.8.8')).toBe('US')
    expect(lookupCountryIn(ranges, '203.0.113.42')).toBe('DE')
  })

  it('returns null for IPs outside any range', () => {
    expect(lookupCountryIn(ranges, '9.9.9.9')).toBeNull()
    expect(lookupCountryIn(ranges, '1.0.4.0')).toBeNull()
  })

  it('returns null for invalid IPs', () => {
    expect(lookupCountryIn(ranges, 'not-an-ip')).toBeNull()
  })

  it('handles range boundaries inclusively', () => {
    expect(lookupCountryIn(ranges, '8.8.8.0')).toBe('US')
    expect(lookupCountryIn(ranges, '8.8.8.255')).toBe('US')
  })
})
