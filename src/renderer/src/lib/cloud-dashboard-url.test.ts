import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { publicCloudDashboardUrl } from './cloud-dashboard-url'

describe('publicCloudDashboardUrl', () => {
  const prev = process.env.BULWRK_CLOUD_URL

  afterEach(() => {
    if (prev === undefined) delete process.env.BULWRK_CLOUD_URL
    else process.env.BULWRK_CLOUD_URL = prev
    vi.unstubAllEnvs()
  })

  beforeEach(() => {
    delete process.env.BULWRK_CLOUD_URL
  })

  it('returns null when unset or placeholder', () => {
    expect(publicCloudDashboardUrl()).toBeNull()
    process.env.BULWRK_CLOUD_URL = 'https://cloud.invalid'
    expect(publicCloudDashboardUrl()).toBeNull()
    process.env.BULWRK_CLOUD_URL = 'https://cloud.usekudu.com'
    expect(publicCloudDashboardUrl()).toBeNull()
  })

  it('returns configured https URL with optional path', () => {
    process.env.BULWRK_CLOUD_URL = 'https://example-cloud.test/'
    expect(publicCloudDashboardUrl()).toBe('https://example-cloud.test')
    expect(publicCloudDashboardUrl('/organisation/billing')).toBe(
      'https://example-cloud.test/organisation/billing',
    )
  })
})
