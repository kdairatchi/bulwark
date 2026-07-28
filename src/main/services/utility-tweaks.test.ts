import { describe, expect, it } from 'vitest'
import {
  POWER_PLAN_GUIDS,
  classifyPowerPlanGuid,
  isPowerPlanGuid,
  listTweaks,
  parseActivePowerSchemeGuid,
  parsePowerSchemeList,
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
