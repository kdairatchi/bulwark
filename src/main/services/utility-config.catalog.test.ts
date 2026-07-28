import { describe, expect, it } from 'vitest'
import {
  UTILITY_CONFIG_FEATURES,
  UTILITY_CONFIG_FIXES,
  UTILITY_LEGACY_PANELS,
} from './utility-config.catalog'

describe('utility-config catalog', () => {
  it('has the expected stable feature IDs', () => {
    expect(UTILITY_CONFIG_FEATURES.map((feature) => feature.id)).toEqual([
      'netfx-all',
      'hyper-v',
      'legacy-media',
      'nfs',
      'wsl',
      'windows-sandbox',
      'telnet-client',
      'tftp-client',
      'containers',
      'f8-boot-recovery',
      'daily-registry-backup',
    ])
  })

  it('has unique IDs across each catalog', () => {
    for (const catalog of [UTILITY_CONFIG_FEATURES, UTILITY_LEGACY_PANELS, UTILITY_CONFIG_FIXES]) {
      const ids = catalog.map((entry) => entry.id)
      expect(new Set(ids).size).toBe(ids.length)
    }
  })

  it('keeps optional feature entries backed by DISM/PowerShell feature names', () => {
    const optionalFeatures = UTILITY_CONFIG_FEATURES.filter((feature) => feature.kind === 'optional-feature')
    expect(optionalFeatures.length).toBeGreaterThan(0)
    for (const feature of optionalFeatures) {
      expect(feature.featureNames?.length, feature.id).toBeGreaterThan(0)
      for (const name of feature.featureNames ?? []) {
        expect(name, `${feature.id}:${name}`).toMatch(/^[A-Za-z0-9.-]+$/)
      }
    }
  })

  it('has the requested legacy panels and fixes', () => {
    expect(UTILITY_LEGACY_PANELS.map((panel) => panel.id)).toEqual([
      'control-panel',
      'network',
      'power',
      'region',
      'sound',
      'system',
      'user-accounts',
    ])
    expect(UTILITY_CONFIG_FIXES.map((fix) => fix.id)).toEqual([
      'reset-network',
      'reset-windows-update',
      'system-corruption-scan',
      'winget-repair',
    ])
  })
})
