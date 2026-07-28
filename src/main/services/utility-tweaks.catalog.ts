/**
 * Curated reversible tweaks for Utility -> Tweaks.
 * Runtime actions intentionally wrap existing Privacy Shield definitions.
 */
export type UtilityTweakGroup = 'essential' | 'advanced'

export interface UtilityTweakDefinition {
  id: string
  name: string
  description: string
  group: UtilityTweakGroup
  requiresAdmin: boolean
  check: () => Promise<boolean>
  apply: () => Promise<void>
  revert: () => Promise<void>
}

interface PrivacySettingDef {
  id: string
  label: string
  description: string
  requiresAdmin: boolean
  check: () => Promise<boolean>
  apply: () => Promise<void>
  revert?: () => Promise<void>
}

function getPrivacySetting(id: string): PrivacySettingDef {
  const { PRIVACY_SETTINGS } = require('../ipc/privacy-shield.ipc') as {
    PRIVACY_SETTINGS: PrivacySettingDef[]
  }
  const setting = PRIVACY_SETTINGS.find((s) => s.id === id)
  if (!setting) throw new Error(`Privacy setting "${id}" not found`)
  if (typeof setting.revert !== 'function') {
    throw new Error(`Privacy setting "${id}" is not reversible`)
  }
  return setting
}

function privacyTweak(
  id: string,
  group: UtilityTweakGroup,
  requiresAdmin: boolean,
  overrides?: Partial<Pick<UtilityTweakDefinition, 'name' | 'description'>>,
): UtilityTweakDefinition {
  return {
    id,
    name: overrides?.name ?? id,
    description: overrides?.description ?? '',
    group,
    requiresAdmin,
    check: () => getPrivacySetting(id).check(),
    apply: () => getPrivacySetting(id).apply(),
    revert: () => getPrivacySetting(id).revert!(),
  }
}

export const UTILITY_TWEAK_CATALOG: UtilityTweakDefinition[] = [
  privacyTweak('telemetry-level', 'essential', true, {
    name: 'Minimize Windows telemetry',
    description: 'Set Windows diagnostic data collection to the minimum policy level.',
  }),
  privacyTweak('activity-history', 'essential', true, {
    name: 'Disable Activity History',
    description: 'Stop Windows from tracking and syncing app and file activity.',
  }),
  privacyTweak('advertising-id', 'essential', false, {
    name: 'Disable Advertising ID',
    description: 'Turn off the per-user advertising identifier used by apps.',
  }),
  privacyTweak('tips-notifications', 'essential', false, {
    name: 'Disable tips and suggestions',
    description: 'Stop Windows tips, tricks, and suggestion notifications.',
  }),
  privacyTweak('bing-start-menu', 'essential', false, {
    name: 'Disable Bing in Start',
    description: 'Keep Start menu searches local instead of sending queries to Bing.',
  }),
  privacyTweak('app-launch-tracking', 'essential', false, {
    name: 'Disable app launch tracking',
    description: 'Stop Windows from tracking app launches to personalize Start.',
  }),
  privacyTweak('clipboard-sync', 'advanced', true, {
    name: 'Disable cloud clipboard sync',
    description: 'Prevent clipboard data from syncing through Microsoft cloud services.',
  }),
  privacyTweak('copilot', 'advanced', true, {
    name: 'Disable Microsoft Copilot',
    description: 'Apply the Windows policy that turns off Microsoft Copilot.',
  }),
  privacyTweak('windows-recall', 'advanced', true, {
    name: 'Disable Windows Recall',
    description: 'Apply the Windows policy that disables Recall AI data analysis.',
  }),
  privacyTweak('service-diagtrack', 'advanced', true, {
    name: 'Disable DiagTrack service',
    description: 'Disable the Connected User Experiences and Telemetry service.',
  }),
  privacyTweak('task-compatibility-appraiser', 'advanced', true, {
    name: 'Disable Compatibility Appraiser task',
    description: 'Disable the scheduled task that collects app compatibility telemetry.',
  }),
]

export const UTILITY_TWEAK_GROUP_ORDER: UtilityTweakGroup[] = ['essential', 'advanced']
