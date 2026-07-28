import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runUtilityInstallActions } from './utility-install'

describe('runUtilityInstallActions', () => {
  const originalPlatform = process.platform

  beforeEach(() => {
    Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
  })

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true })
  })

  it('rejects non-catalog package IDs before platform or winget checks', async () => {
    const result = await runUtilityInstallActions('install', ['Microsoft.Teams'])

    expect(result).toEqual({
      succeeded: 0,
      failed: 1,
      errors: [
        { id: 'Microsoft.Teams', reason: 'Package ID is not in the utility catalog' },
      ],
    })
  })

  it('reports non-catalog IDs separately from catalog IDs', async () => {
    const result = await runUtilityInstallActions('install', ['Google.Chrome', 'Microsoft.Teams'])

    expect(result.succeeded).toBe(0)
    expect(result.failed).toBe(2)
    expect(result.errors).toContainEqual({
      id: 'Microsoft.Teams',
      reason: 'Package ID is not in the utility catalog',
    })
    expect(result.errors).toContainEqual({ id: 'Google.Chrome', reason: 'Windows only' })
  })
})
