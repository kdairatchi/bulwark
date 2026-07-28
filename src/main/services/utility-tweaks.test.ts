import { describe, expect, it } from 'vitest'
import {
  POWER_PLAN_GUIDS,
  buildUtilityTweakPreset,
  classifyPowerPlanGuid,
  filterKnownUtilityTweakIds,
  isPowerPlanGuid,
  listTweaks,
  parseActivePowerSchemeGuid,
  parsePowerSchemeList,
  parseUtilityTweakPreset,
  validateUtilityTweakIds,
} from './utility-tweaks'

describe('utility-tweaks helpers', () => {
  it('validates tweak IDs strictly against the catalog', () => {
    const [first] = listTweaks()

    expect(validateUtilityTweakIds([first.id, first.id])).toEqual([first.id])
    expect(validateUtilityTweakIds(['not-a-real-tweak'])).toBeNull()
    expect(validateUtilityTweakIds([first.id, 42])).toBeNull()
    expect(validateUtilityTweakIds('telemetry-level')).toBeNull()
  })

  it('soft-filters known tweak IDs for preset import', () => {
    const [first, second] = listTweaks()
    expect(filterKnownUtilityTweakIds([first.id, 'nope', second.id, first.id])).toEqual({
      selected: [first.id, second.id],
      skipped: 1,
    })
    expect(filterKnownUtilityTweakIds('bad')).toBeNull()
  })

  it('builds and parses portable tweak preset JSON', () => {
    const [first] = listTweaks()
    const file = buildUtilityTweakPreset([first.id], { [first.id]: true, unknown: true })
    expect(file).toEqual({
      version: 1,
      kind: 'bulwrk-utility-tweaks',
      selected: [first.id],
      applied: { [first.id]: true },
    })

    expect(parseUtilityTweakPreset(file)).toEqual({ selected: [first.id], skipped: 0 })
    expect(parseUtilityTweakPreset({
      version: 1,
      kind: 'bulwrk-utility-tweaks',
      selected: [first.id, 'ghost-tweak'],
    })).toEqual({ selected: [first.id], skipped: 1 })
    expect(parseUtilityTweakPreset({ version: 2, kind: 'bulwrk-utility-tweaks', selected: [first.id] })).toBeNull()
    expect(parseUtilityTweakPreset({ version: 1, kind: 'other', selected: [first.id] })).toBeNull()
  })

  it('exports valid Windows power plan GUID constants', () => {
    expect(isPowerPlanGuid(POWER_PLAN_GUIDS.balanced)).toBe(true)
    expect(isPowerPlanGuid(POWER_PLAN_GUIDS.ultimatePerformance)).toBe(true)
    expect(isPowerPlanGuid('not-a-guid')).toBe(false)
  })

  it('parses active power scheme GUID output', () => {
    expect(parseActivePowerSchemeGuid(
      'Power Scheme GUID: 381B4222-F694-41F0-9685-FF5BB260DF2E  (Balanced)',
    )).toBe(POWER_PLAN_GUIDS.balanced)

    expect(parseActivePowerSchemeGuid('no active plan')).toBeNull()
  })

  it('parses listed power schemes and marks the active scheme', () => {
    const output = [
      'Existing Power Schemes (* Active)',
      '-----------------------------------',
      'Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *',
      'Power Scheme GUID: e9a42b02-d5df-448d-aa00-03f14749eb61  (Ultimate Performance)',
    ].join('\n')

    expect(parsePowerSchemeList(output)).toEqual([
      { guid: POWER_PLAN_GUIDS.balanced, name: 'Balanced', active: true },
      {
        guid: POWER_PLAN_GUIDS.ultimatePerformance,
        name: 'Ultimate Performance',
        active: false,
      },
    ])
  })

  it('classifies known and unknown power plan GUIDs', () => {
    expect(classifyPowerPlanGuid(POWER_PLAN_GUIDS.balanced)).toBe('balanced')
    expect(classifyPowerPlanGuid(POWER_PLAN_GUIDS.ultimatePerformance)).toBe('ultimate-performance')
    expect(classifyPowerPlanGuid('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')).toBe('other')
    expect(classifyPowerPlanGuid(null)).toBe('unknown')
  })
})
