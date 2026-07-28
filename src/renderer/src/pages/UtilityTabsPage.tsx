import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Download,
  SlidersHorizontal,
  Settings2,
  Search,
  RefreshCw,
  CheckSquare,
  Square,
  PackagePlus,
  ArrowUpCircle,
  Trash2,
  Eraser,
  AlertTriangle,
  Loader2,
  ShieldCheck,
  Zap,
  ExternalLink,
  CheckCircle2,
  CircleDashed,
  Server,
  Wrench,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { PageHeader } from '@/components/layout/PageHeader'
import { EmptyState } from '@/components/shared/EmptyState'
import { cn } from '@/lib/utils'
import { usePlatform } from '@/hooks/usePlatform'
import type { LucideIcon } from 'lucide-react'
import type {
  UtilityCatalogApp,
  UtilityInstallActionResult,
  UtilityInstalledMap,
  UtilityPowerPlanTarget,
  UtilityConfigActionResult,
  UtilityConfigCatalogResult,
  UtilityConfigFeatureMetadata,
  UtilityConfigFeatureStatus,
  UtilityConfigFeatureStatusResult,
  UtilityConfigFixMetadata,
  UtilityConfigOpenSshStatusResult,
  UtilityTweakActionResult,
  UtilityTweakMetadata,
} from '@shared/types'

interface TabDef {
  id: 'install' | 'tweaks' | 'config'
  labelKey: string
  descriptionKey: string
  icon: LucideIcon
}

const TABS: TabDef[] = [
  { id: 'install', labelKey: 'tabs.install', descriptionKey: 'tabs.installDescription', icon: Download },
  { id: 'tweaks', labelKey: 'tabs.tweaks', descriptionKey: 'tabs.tweaksDescription', icon: SlidersHorizontal },
  { id: 'config', labelKey: 'tabs.config', descriptionKey: 'tabs.configDescription', icon: Settings2 },
]

const CATEGORY_ORDER = ['browsers', 'utilities', 'media', 'communication', 'development', 'security']
const REVERSIBLE_CONFIG_FEATURE_IDS = new Set(['f8-boot-recovery', 'daily-registry-backup'])
const DESTRUCTIVE_CONFIG_FIX_IDS = new Set(['reset-network', 'reset-windows-update'])

function reportActionResult(t: (k: string, o?: Record<string, unknown>) => string, result: UtilityInstallActionResult) {
  if (result.succeeded > 0) toast.success(t('install.toastSuccess', { count: result.succeeded }))
  if (result.failed > 0) {
    const detail = result.errors.slice(0, 3).map((e) => `${e.id}: ${e.reason}`).join('\n')
    toast.error(t('install.toastFailed', { count: result.failed }), { description: detail || undefined })
  }
}

function reportTweakActionResult(t: (k: string, o?: Record<string, unknown>) => string, result: UtilityTweakActionResult) {
  if (result.restorePoint && !result.restorePoint.success) {
    toast.error(t('tweaks.restorePointFailed'), {
      description: result.restorePoint.error,
    })
  }
  if (result.succeeded > 0) toast.success(t('tweaks.toastSuccess', { count: result.succeeded }))
  if (result.failed > 0) {
    const detail = result.errors.slice(0, 3).map((e) => `${e.id}: ${e.reason}`).join('\n')
    toast.error(t('tweaks.toastFailed', { count: result.failed }), { description: detail || undefined })
  }
}

function reportConfigActionResult(t: (k: string, o?: Record<string, unknown>) => string, result: UtilityConfigActionResult) {
  if (result.success) {
    toast.success(result.summary, {
      description: result.requiresReboot ? t('config.rebootRequired') : undefined,
    })
    return
  }

  if (result.needsAdmin) {
    toast.error(t('config.adminRequired'), { description: result.error || result.summary })
    return
  }

  toast.error(result.summary || t('config.toastActionFailed'), {
    description: result.error,
  })
}

function configStatusClass(status: UtilityConfigFeatureStatus | 'loading') {
  if (status === 'enabled') return 'text-green-400'
  if (status === 'partial') return 'text-amber-300'
  if (status === 'disabled') return 'text-zinc-400'
  if (status === 'unavailable') return 'text-red-300'
  return 'text-zinc-500'
}

function configStatusIcon(status: UtilityConfigFeatureStatus | 'loading') {
  if (status === 'enabled') return CheckCircle2
  if (status === 'disabled') return XCircle
  if (status === 'loading') return Loader2
  return CircleDashed
}

interface UtilityProgressState {
  message: string
  current: number
  total: number
}

function UtilityProgressBar({
  progress,
  fallback,
}: {
  progress: UtilityProgressState | null
  fallback: string
}) {
  const message = progress?.message || fallback
  const total = progress?.total ?? 0
  const current = progress?.current ?? 0
  const pct = total > 0 ? Math.min(100, Math.round((current / total) * 100)) : null

  return (
    <div className="min-w-0 flex-1 space-y-1.5">
      <div className="flex items-center justify-end gap-2 text-amber-400">
        <Loader2 className="h-3 w-3 animate-spin shrink-0" />
        <span className="truncate text-right">{message}</span>
        {pct !== null && (
          <span className="shrink-0 font-mono text-[10px] text-amber-300/80">
            {current}/{total}
          </span>
        )}
      </div>
      {pct !== null && (
        <div className="h-1.5 overflow-hidden rounded-full" style={{ background: 'rgba(245,158,11,0.15)' }}>
          <div
            className="h-full rounded-full transition-[width] duration-300"
            style={{ width: `${pct}%`, background: 'rgb(245,158,11)' }}
          />
        </div>
      )}
    </div>
  )
}

function InstallTab() {
  const { t } = useTranslation('utilities')
  const searchRef = useRef<HTMLInputElement>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<UtilityProgressState | null>(null)
  const [wingetAvailable, setWingetAvailable] = useState(false)
  const [apps, setApps] = useState<UtilityCatalogApp[]>([])
  const [installed, setInstalled] = useState<UtilityInstalledMap>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [query, setQuery] = useState('')

  const load = useCallback(async (refresh = false) => {
    setLoading(true)
    try {
      const result = refresh
        ? await window.kudu.utilityInstallRefresh()
        : await window.kudu.utilityInstallCatalog()
      setWingetAvailable(result.wingetAvailable)
      setApps(result.apps)
      setInstalled(result.installed)
    } catch {
      toast.error('Failed to load utility catalog')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load(false)
    const off = window.kudu.onUtilityInstallProgress?.((p) => {
      setProgress({
        message: p.message,
        current: p.current,
        total: p.total,
      })
    })
    return () => { off?.() }
  }, [load])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault()
        searchRef.current?.focus()
        searchRef.current?.select()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return apps
    return apps.filter(
      (a) =>
        a.name.toLowerCase().includes(q)
        || a.id.toLowerCase().includes(q)
        || a.category.toLowerCase().includes(q),
    )
  }, [apps, query])

  const grouped = useMemo(() => {
    const map = new Map<string, UtilityCatalogApp[]>()
    for (const cat of CATEGORY_ORDER) map.set(cat, [])
    for (const app of filtered) {
      const list = map.get(app.category) || []
      list.push(app)
      map.set(app.category, list)
    }
    return [...map.entries()].filter(([, list]) => list.length > 0)
  }, [filtered])

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const clearSelection = () => setSelected(new Set())

  const toggleCategory = (list: UtilityCatalogApp[]) => {
    setSelected((prev) => {
      const next = new Set(prev)
      const allSelected = list.length > 0 && list.every((app) => next.has(app.id))
      if (allSelected) {
        for (const app of list) next.delete(app.id)
      } else {
        for (const app of list) next.add(app.id)
      }
      return next
    })
  }

  const runInstallOrUpgrade = async () => {
    if (selected.size === 0) {
      toast.error(t('install.toastNothingSelected'))
      return
    }
    setRunning(true)
    setProgress(null)
    try {
      const ids = [...selected]
      const toInstall = ids.filter((id) => !installed[id])
      const toUpgrade = ids.filter((id) => !!installed[id])
      let combined: UtilityInstallActionResult = { succeeded: 0, failed: 0, errors: [] }
      if (toInstall.length > 0) {
        const r = await window.kudu.utilityInstallRun({ action: 'install', ids: toInstall })
        combined = {
          succeeded: combined.succeeded + r.succeeded,
          failed: combined.failed + r.failed,
          errors: [...combined.errors, ...r.errors],
        }
      }
      if (toUpgrade.length > 0) {
        const r = await window.kudu.utilityInstallRun({ action: 'upgrade', ids: toUpgrade })
        combined = {
          succeeded: combined.succeeded + r.succeeded,
          failed: combined.failed + r.failed,
          errors: [...combined.errors, ...r.errors],
        }
      }
      reportActionResult(t, combined)
      await load(true)
    } catch {
      toast.error(t('install.toastFailed', { count: selected.size }))
    } finally {
      setRunning(false)
      setProgress(null)
    }
  }

  const runUninstall = async () => {
    if (selected.size === 0) {
      toast.error(t('install.toastNothingSelected'))
      return
    }
    setRunning(true)
    setProgress(null)
    try {
      const result = await window.kudu.utilityInstallRun({
        action: 'uninstall',
        ids: [...selected],
      })
      reportActionResult(t, result)
      await load(true)
    } catch {
      toast.error(t('install.toastFailed', { count: selected.size }))
    } finally {
      setRunning(false)
      setProgress(null)
    }
  }

  const runUpgradeAll = async () => {
    setRunning(true)
    setProgress(null)
    try {
      const result = await window.kudu.utilityInstallUpgradeAll()
      reportActionResult(t, result)
      await load(true)
    } catch {
      toast.error(t('install.toastFailed', { count: 1 }))
    } finally {
      setRunning(false)
      setProgress(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-[13px]" style={{ color: 'var(--text-muted)' }}>
        <Loader2 className="h-4 w-4 animate-spin" />
        {t('install.loading')}
      </div>
    )
  }

  if (!wingetAvailable) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title={t('install.wingetMissing')}
        description={t('install.wingetMissingHint')}
      />
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-[15px] font-semibold text-zinc-100">{t('install.heading')}</h2>
        <p className="text-[12px] mt-1" style={{ color: 'var(--text-muted)' }}>{t('install.description')}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={running || selected.size === 0}
          onClick={() => void runInstallOrUpgrade()}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--accent)', color: 'white' }}
        >
          <PackagePlus className="h-3.5 w-3.5" />
          {t('install.installUpgrade')}
        </button>
        <button
          type="button"
          disabled={running}
          onClick={() => void runUpgradeAll()}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
        >
          <ArrowUpCircle className="h-3.5 w-3.5" />
          {t('install.upgradeAll')}
        </button>
        <button
          type="button"
          disabled={running || selected.size === 0}
          onClick={() => void runUninstall()}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40 text-red-300"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <Trash2 className="h-3.5 w-3.5" />
          {t('install.uninstall')}
        </button>
        <button
          type="button"
          disabled={running}
          onClick={() => void load(true)}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          {t('install.getInstalled')}
        </button>
        <button
          type="button"
          disabled={running || selected.size === 0}
          onClick={clearSelection}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
        >
          <Eraser className="h-3.5 w-3.5" />
          {t('install.clearSelection')}
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={t('install.searchPlaceholder')}
          className="w-full rounded-xl pl-9 pr-3 py-2.5 text-[13px] outline-none"
          style={{
            background: 'var(--card-bg)',
            border: '1px solid var(--border-default)',
            color: 'var(--text-primary)',
          }}
        />
      </div>

      <div className="flex items-start justify-between gap-4 text-[11px]" style={{ color: 'var(--text-muted)' }}>
        <span className="shrink-0 pt-0.5">{t('install.selectedCount', { count: selected.size })}</span>
        {running && (
          <UtilityProgressBar progress={progress} fallback={t('install.running')} />
        )}
      </div>

      {grouped.length === 0 ? (
        <p className="text-[13px] py-8 text-center" style={{ color: 'var(--text-muted)' }}>{t('install.noMatches')}</p>
      ) : (
        <div className="space-y-4">
          {grouped.map(([category, list]) => {
            const categorySelectedCount = list.filter((app) => selected.has(app.id)).length
            const categoryAllSelected = list.length > 0 && categorySelectedCount === list.length
            return (
            <div
              key={category}
              className="rounded-2xl overflow-hidden"
              style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
            >
              <button
                type="button"
                disabled={running}
                onClick={() => toggleCategory(list)}
                className="w-full flex items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-white/[0.02] disabled:opacity-50"
                style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-default)' }}
                title={t('install.selectCategory')}
              >
                {categoryAllSelected ? (
                  <CheckSquare className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                ) : (
                  <Square className="h-3.5 w-3.5 shrink-0" />
                )}
                <span className="text-[11px] font-semibold uppercase tracking-wider">
                  {t(`install.categories.${category}`, { defaultValue: category })}
                </span>
                <span className="text-[10px] font-normal normal-case tracking-normal">
                  ({categorySelectedCount}/{list.length})
                </span>
              </button>
              <ul>
                {list.map((app) => {
                  const isOn = !!installed[app.id]
                  const isSelected = selected.has(app.id)
                  return (
                    <li key={app.id}>
                      <button
                        type="button"
                        disabled={running}
                        onClick={() => toggle(app.id)}
                        className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-white/[0.02] disabled:opacity-50"
                      >
                        {isSelected ? (
                          <CheckSquare className="h-4 w-4 text-amber-400 shrink-0" />
                        ) : (
                          <Square className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
                        )}
                        <div className="min-w-0 flex-1">
                          <p className="text-[13px] font-medium text-zinc-200 truncate">{app.name}</p>
                          <p className="text-[11px] font-mono truncate" style={{ color: 'var(--text-faint)' }}>{app.id}</p>
                        </div>
                        <span
                          className={cn(
                            'text-[10px] font-medium rounded-md px-2 py-0.5 shrink-0',
                            isOn ? 'text-green-400' : 'text-zinc-500',
                          )}
                          style={{
                            background: isOn ? 'rgba(34,197,94,0.1)' : 'rgba(113,113,122,0.1)',
                          }}
                        >
                          {isOn
                            ? `${t('install.installed')}${installed[app.id]?.version ? ` · ${installed[app.id].version}` : ''}`
                            : t('install.notInstalled')}
                        </span>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function TweaksTab() {
  const { t } = useTranslation('utilities')
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [powerPlanRunning, setPowerPlanRunning] = useState(false)
  const [tweaks, setTweaks] = useState<UtilityTweakMetadata[]>([])
  const [applied, setApplied] = useState<Record<string, boolean>>({})
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [powerPlan, setPowerPlan] = useState<'balanced' | 'ultimate-performance' | 'other' | 'unknown'>('unknown')
  const [powerPlanAvailable, setPowerPlanAvailable] = useState(false)

  const essentialTweaks = useMemo(() => tweaks.filter((tweak) => tweak.group === 'essential'), [tweaks])
  const advancedTweaks = useMemo(() => tweaks.filter((tweak) => tweak.group === 'advanced'), [tweaks])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [catalog, plan] = await Promise.all([
        window.kudu.utilityTweaksCatalog(),
        window.kudu.utilityTweaksPowerPlanGet(),
      ])
      setTweaks(catalog)
      setPowerPlan(plan.active)
      setPowerPlanAvailable(plan.available)
      if (!plan.available && plan.error) {
        toast.error(t('tweaks.powerPlanUnavailable'), { description: plan.error })
      }
    } catch {
      toast.error(t('tweaks.toastLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    void load()
  }, [load])

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectIds = (ids: string[]) => setSelected(new Set(ids))

  const applyPreset = (preset: 'minimal' | 'standard' | 'advanced' | 'clear') => {
    if (preset === 'clear') {
      setSelected(new Set())
      return
    }
    if (preset === 'minimal') {
      selectIds(essentialTweaks.slice(0, 3).map((tweak) => tweak.id))
      return
    }
    if (preset === 'standard') {
      selectIds(essentialTweaks.map((tweak) => tweak.id))
      return
    }
    selectIds(tweaks.map((tweak) => tweak.id))
  }

  const scanInstalled = async () => {
    setScanning(true)
    try {
      const result = await window.kudu.utilityTweaksScan()
      setTweaks(result.tweaks)
      setApplied(result.applied)
      setPowerPlan(result.powerPlan.active)
      setPowerPlanAvailable(result.powerPlan.available)
      if (!result.available) {
        toast.error(t('tweaks.windowsOnly'))
        return
      }
      const count = Object.values(result.applied).filter(Boolean).length
      toast.success(t('tweaks.toastScanComplete', { count }))
    } catch {
      toast.error(t('tweaks.toastScanFailed'))
    } finally {
      setScanning(false)
    }
  }

  const runTweaks = async (action: 'apply' | 'revert') => {
    if (selected.size === 0) {
      toast.error(t('tweaks.toastNothingSelected'))
      return
    }
    setRunning(true)
    try {
      const ids = [...selected]
      const result = action === 'apply'
        ? await window.kudu.utilityTweaksApply(ids)
        : await window.kudu.utilityTweaksRevert(ids)
      reportTweakActionResult(t, result)
      await scanInstalled()
    } catch {
      toast.error(t('tweaks.toastFailed', { count: selected.size }))
    } finally {
      setRunning(false)
    }
  }

  const setPlan = async (target: UtilityPowerPlanTarget) => {
    setPowerPlanRunning(true)
    try {
      const result = await window.kudu.utilityTweaksPowerPlanSet(target)
      if (!result.success) {
        toast.error(t('tweaks.powerPlanSetFailed'), { description: result.error })
        return
      }
      if (result.state) {
        setPowerPlan(result.state.active)
        setPowerPlanAvailable(result.state.available)
      }
      toast.success(t('tweaks.powerPlanSetSuccess'))
    } catch {
      toast.error(t('tweaks.powerPlanSetFailed'))
    } finally {
      setPowerPlanRunning(false)
    }
  }

  const launchShutUp = async () => {
    try {
      const result = await window.kudu.utilityTweaksLaunchShutUp10()
      toast.success(result.fallback ? t('tweaks.shutUpDownloadOpened') : t('tweaks.shutUpOpened'))
    } catch {
      toast.error(t('tweaks.shutUpFailed'))
    }
  }

  const renderSection = (title: string, description: string, items: UtilityTweakMetadata[], caution = false) => (
    <section
      className="rounded-2xl overflow-hidden"
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
    >
      <div
        className="px-4 py-3"
        style={{ borderBottom: '1px solid var(--border-default)' }}
      >
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-[13px] font-semibold text-zinc-100">{title}</h3>
            <p className="text-[11px] mt-0.5" style={{ color: 'var(--text-muted)' }}>{description}</p>
          </div>
          <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
            {t('tweaks.sectionCount', { count: items.length })}
          </span>
        </div>
        {caution && (
          <div
            className="mt-3 flex items-start gap-2 rounded-lg px-3 py-2 text-[11px] text-amber-200"
            style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.18)' }}
          >
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            <span>{t('tweaks.advancedCaution')}</span>
          </div>
        )}
      </div>
      <ul>
        {items.map((tweak) => {
          const isSelected = selected.has(tweak.id)
          const isApplied = !!applied[tweak.id]
          return (
            <li key={tweak.id}>
              <button
                type="button"
                disabled={running || scanning}
                onClick={() => toggle(tweak.id)}
                className="w-full flex items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-white/[0.02] disabled:opacity-50"
              >
                {isSelected ? (
                  <CheckSquare className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                ) : (
                  <Square className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }} />
                )}
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[13px] font-medium text-zinc-200">{tweak.name}</p>
                    {isApplied && (
                      <span className="rounded-md px-2 py-0.5 text-[10px] font-medium text-green-400" style={{ background: 'rgba(34,197,94,0.1)' }}>
                        {t('tweaks.appliedBadge')}
                      </span>
                    )}
                    {tweak.requiresAdmin && (
                      <span className="rounded-md px-2 py-0.5 text-[10px] font-medium text-amber-300" style={{ background: 'rgba(245,158,11,0.08)' }}>
                        {t('tweaks.adminBadge')}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>{tweak.description}</p>
                  <p className="text-[10px] font-mono mt-1" style={{ color: 'var(--text-faint)' }}>{tweak.id}</p>
                </div>
              </button>
            </li>
          )
        })}
      </ul>
    </section>
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-[13px]" style={{ color: 'var(--text-muted)' }}>
        <Loader2 className="h-4 w-4 animate-spin" />
        {t('tweaks.loading')}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-[15px] font-semibold text-zinc-100">{t('tweaks.heading')}</h2>
        <p className="text-[12px] mt-1" style={{ color: 'var(--text-muted)' }}>{t('tweaks.description')}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {(['minimal', 'standard', 'advanced', 'clear'] as const).map((preset) => (
          <button
            key={preset}
            type="button"
            disabled={running || scanning}
            onClick={() => applyPreset(preset)}
            className="rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
            style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
          >
            {t(`tweaks.presets.${preset}`)}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={running || selected.size === 0}
          onClick={() => void runTweaks('apply')}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--accent)', color: 'white' }}
        >
          {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
          {t('tweaks.runTweaks')}
        </button>
        <button
          type="button"
          disabled={running || selected.size === 0}
          onClick={() => void runTweaks('revert')}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40 text-red-300"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          {t('tweaks.undoSelected')}
        </button>
        <button
          type="button"
          disabled={running || scanning}
          onClick={() => void scanInstalled()}
          className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
        >
          {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          {t('tweaks.getInstalled')}
        </button>
      </div>

      <div className="flex items-center justify-between text-[11px]" style={{ color: 'var(--text-muted)' }}>
        <span>{t('tweaks.selectedCount', { count: selected.size })}</span>
        {(running || scanning) && (
          <span className="flex items-center gap-1.5 text-amber-400">
            <Loader2 className="h-3 w-3 animate-spin" />
            {running ? t('tweaks.running') : t('tweaks.scanning')}
          </span>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-4">
          {renderSection(t('tweaks.essentialTitle'), t('tweaks.essentialDescription'), essentialTweaks)}
          {renderSection(t('tweaks.advancedTitle'), t('tweaks.advancedDescription'), advancedTweaks, true)}
        </div>

        <aside className="space-y-4">
          <section
            className="rounded-2xl p-4"
            style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
          >
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              <h3 className="text-[13px] font-semibold text-zinc-100">{t('tweaks.powerPlansTitle')}</h3>
            </div>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('tweaks.powerPlansDescription')}</p>
            <div className="mt-3 grid gap-2">
              {(['ultimate-performance', 'balanced'] as UtilityPowerPlanTarget[]).map((target) => {
                const active = powerPlan === target
                return (
                  <button
                    key={target}
                    type="button"
                    disabled={!powerPlanAvailable || powerPlanRunning}
                    onClick={() => void setPlan(target)}
                    className={cn(
                      'flex items-center justify-between rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40',
                      active ? 'text-amber-300' : 'text-zinc-300',
                    )}
                    style={{
                      background: active ? 'var(--accent-muted-bg)' : 'var(--bg-subtle)',
                      border: '1px solid var(--border-default)',
                    }}
                  >
                    <span>{t(`tweaks.powerPlans.${target}`)}</span>
                    {active && <span className="text-[10px]">{t('tweaks.activePlan')}</span>}
                  </button>
                )
              })}
            </div>
            {!powerPlanAvailable && (
              <p className="mt-3 text-[11px] text-amber-300">{t('tweaks.powerPlanUnavailable')}</p>
            )}
          </section>

          <section
            className="rounded-2xl p-4"
            style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
          >
            <h3 className="text-[13px] font-semibold text-zinc-100">{t('tweaks.shutUpTitle')}</h3>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('tweaks.shutUpDescription')}</p>
            <button
              type="button"
              onClick={() => void launchShutUp()}
              className="mt-3 flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium"
              style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
            >
              <ExternalLink className="h-3.5 w-3.5" />
              {t('tweaks.shutUpLaunch')}
            </button>
          </section>
        </aside>
      </div>
    </div>
  )
}

function ConfigTab() {
  const { t } = useTranslation('utilities')
  const [loading, setLoading] = useState(true)
  const [statusLoading, setStatusLoading] = useState(false)
  const [runningId, setRunningId] = useState<string | null>(null)
  const [catalog, setCatalog] = useState<UtilityConfigCatalogResult | null>(null)
  const [featureStatus, setFeatureStatus] = useState<Record<string, UtilityConfigFeatureStatusResult>>({})
  const [openSshStatus, setOpenSshStatus] = useState<UtilityConfigOpenSshStatusResult | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [progress, setProgress] = useState<UtilityProgressState | null>(null)

  const busy = runningId !== null

  const loadFeatureStatuses = useCallback(async (features: UtilityConfigFeatureMetadata[]) => {
    setStatusLoading(true)
    try {
      const statuses = await Promise.all(features.map(async (feature) => {
        try {
          return await window.kudu.utilityConfigFeatureStatus(feature.id)
        } catch {
          return {
            id: feature.id,
            available: false,
            enabled: null,
            status: 'unknown' as const,
            details: t('config.statusLoadFailed'),
          }
        }
      }))
      setFeatureStatus(Object.fromEntries(statuses.map((status) => [status.id, status])))
    } finally {
      setStatusLoading(false)
    }
  }, [t])

  const loadOpenSshStatus = useCallback(async (enabled: boolean) => {
    if (!enabled) {
      setOpenSshStatus(null)
      return
    }
    try {
      setOpenSshStatus(await window.kudu.utilityConfigOpenSshStatus())
    } catch {
      setOpenSshStatus({
        available: false,
        installed: false,
        serviceRunning: false,
        startupType: null,
        details: t('config.statusLoadFailed'),
      })
    }
  }, [t])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const nextCatalog = await window.kudu.utilityConfigCatalog()
      setCatalog(nextCatalog)
      setSelected(new Set())
      if (!nextCatalog.available) {
        setFeatureStatus({})
        setOpenSshStatus(null)
        return
      }
      await Promise.all([
        loadFeatureStatuses(nextCatalog.features),
        loadOpenSshStatus(!!nextCatalog.openSsh),
      ])
    } catch {
      toast.error(t('config.toastLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [loadFeatureStatuses, loadOpenSshStatus, t])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    const off = window.kudu.onUtilityConfigFixProgress?.((p) => {
      setProgress({
        message: p.message,
        current: p.current,
        total: p.total,
      })
    })
    return () => { off?.() }
  }, [])

  const toggleFeature = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const refreshStatuses = async () => {
    if (!catalog?.available) return
    await Promise.all([
      loadFeatureStatuses(catalog.features),
      loadOpenSshStatus(!!catalog.openSsh),
    ])
  }

  const runSelectedFeatures = async () => {
    if (!catalog || selected.size === 0) {
      toast.error(t('config.toastNothingSelected'))
      return
    }
    setRunningId('features-enable')
    try {
      for (const id of selected) {
        const result = await window.kudu.utilityConfigFeatureEnable(id)
        reportConfigActionResult(t, result)
      }
      await loadFeatureStatuses(catalog.features)
    } catch {
      toast.error(t('config.toastActionFailed'))
    } finally {
      setRunningId(null)
    }
  }

  const revertFeature = async (id: string) => {
    if (!catalog) return
    setRunningId(`feature-revert:${id}`)
    try {
      const result = await window.kudu.utilityConfigFeatureRevert(id)
      reportConfigActionResult(t, result)
      await loadFeatureStatuses(catalog.features)
    } catch {
      toast.error(t('config.toastActionFailed'))
    } finally {
      setRunningId(null)
    }
  }

  const launchPanel = async (id: string) => {
    setRunningId(`panel:${id}`)
    try {
      const result = await window.kudu.utilityConfigPanelLaunch(id)
      if (result.launched) {
        toast.success(t('config.panelLaunched'))
      } else {
        toast.error(t('config.panelLaunchFailed'), { description: result.error })
      }
    } catch {
      toast.error(t('config.panelLaunchFailed'))
    } finally {
      setRunningId(null)
    }
  }

  const enableOpenSsh = async () => {
    if (!catalog?.openSsh) return
    setRunningId('openssh')
    try {
      const result = await window.kudu.utilityConfigOpenSshEnable()
      reportConfigActionResult(t, result)
      await loadOpenSshStatus(true)
    } catch {
      toast.error(t('config.toastActionFailed'))
    } finally {
      setRunningId(null)
    }
  }

  const runFix = async (fix: UtilityConfigFixMetadata) => {
    if (DESTRUCTIVE_CONFIG_FIX_IDS.has(fix.id) && !window.confirm(t('config.fixConfirm', { name: fix.name }))) {
      return
    }
    setRunningId(`fix:${fix.id}`)
    setProgress(null)
    try {
      const result = await window.kudu.utilityConfigFixRun(fix.id)
      reportConfigActionResult(t, result)
    } catch {
      toast.error(t('config.toastActionFailed'))
    } finally {
      setRunningId(null)
      setProgress(null)
    }
  }

  const renderAdminBadge = (show: boolean) => show ? (
    <span className="rounded-md px-2 py-0.5 text-[10px] font-medium text-amber-300" style={{ background: 'rgba(245,158,11,0.08)' }}>
      {t('config.adminBadge')}
    </span>
  ) : null

  const renderRebootBadge = (show: boolean) => show ? (
    <span className="rounded-md px-2 py-0.5 text-[10px] font-medium text-sky-300" style={{ background: 'rgba(14,165,233,0.08)' }}>
      {t('config.rebootBadge')}
    </span>
  ) : null

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-16 text-[13px]" style={{ color: 'var(--text-muted)' }}>
        <Loader2 className="h-4 w-4 animate-spin" />
        {t('config.loading')}
      </div>
    )
  }

  if (!catalog?.available) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title={t('config.windowsOnlyTitle')}
        description={t('config.windowsOnlyDescription')}
      />
    )
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-[15px] font-semibold text-zinc-100">{t('config.heading')}</h2>
        <p className="text-[12px] mt-1" style={{ color: 'var(--text-muted)' }}>{t('config.description')}</p>
      </div>

      <section
        className="rounded-2xl overflow-hidden"
        style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      >
        <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border-default)' }}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-amber-400" />
                <h3 className="text-[13px] font-semibold text-zinc-100">{t('config.featuresTitle')}</h3>
              </div>
              <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('config.featuresDescription')}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || selected.size === 0}
                onClick={() => void runSelectedFeatures()}
                className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                style={{ background: 'var(--accent)', color: 'white' }}
              >
                {runningId === 'features-enable' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                {t('config.enableSelected')}
              </button>
              <button
                type="button"
                disabled={busy || statusLoading}
                onClick={() => void refreshStatuses()}
                className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
              >
                {statusLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                {t('config.refreshStatus')}
              </button>
              <button
                type="button"
                disabled={busy || selected.size === 0}
                onClick={() => setSelected(new Set())}
                className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
              >
                <Eraser className="h-3.5 w-3.5" />
                {t('config.clearSelection')}
              </button>
            </div>
          </div>
          <div className="mt-3 flex items-start justify-between gap-4 text-[11px]" style={{ color: 'var(--text-muted)' }}>
            <span className="shrink-0 pt-0.5">{t('config.selectedCount', { count: selected.size })}</span>
            {(busy || statusLoading) && (
              statusLoading ? (
                <span className="flex items-center gap-1.5 text-amber-400">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  {t('config.scanning')}
                </span>
              ) : (
                <UtilityProgressBar progress={progress} fallback={t('config.running')} />
              )
            )}
          </div>
        </div>
        <ul>
          {catalog.features.map((feature) => {
            const status = featureStatus[feature.id]
            const badgeStatus = statusLoading && !status ? 'loading' : status?.status ?? 'unknown'
            const StatusIcon = configStatusIcon(badgeStatus)
            const unavailable = status?.status === 'unavailable'
            const isSelected = selected.has(feature.id)
            const canRevert = REVERSIBLE_CONFIG_FEATURE_IDS.has(feature.id)
            return (
              <li key={feature.id} className="flex items-stretch gap-2 px-4 py-3 hover:bg-white/[0.02]">
                <button
                  type="button"
                  disabled={busy || unavailable}
                  onClick={() => toggleFeature(feature.id)}
                  className="min-w-0 flex flex-1 items-start gap-3 text-left disabled:opacity-50"
                >
                  {isSelected ? (
                    <CheckSquare className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                  ) : (
                    <Square className="h-4 w-4 shrink-0 mt-0.5" style={{ color: 'var(--text-muted)' }} />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="text-[13px] font-medium text-zinc-200">{feature.name}</p>
                      <span
                        className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-medium', configStatusClass(badgeStatus))}
                        style={{ background: 'rgba(113,113,122,0.1)' }}
                      >
                        <StatusIcon className={cn('h-3 w-3', badgeStatus === 'loading' && 'animate-spin')} />
                        {t(`config.status.${badgeStatus}`)}
                      </span>
                      {renderAdminBadge(feature.requiresAdmin)}
                    </div>
                    <p className="text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>{feature.description}</p>
                    {status?.details && (
                      <p className="text-[10px] mt-1" style={{ color: 'var(--text-faint)' }}>{status.details}</p>
                    )}
                    {feature.notes && (
                      <p className="text-[10px] mt-1 text-amber-200">{feature.notes}</p>
                    )}
                    <p className="text-[10px] font-mono mt-1" style={{ color: 'var(--text-faint)' }}>{feature.id}</p>
                  </div>
                </button>
                {canRevert && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void revertFeature(feature.id)}
                    className="self-center rounded-lg px-3 py-2 text-[12px] font-medium text-red-300 disabled:opacity-40"
                    style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}
                  >
                    {runningId === `feature-revert:${feature.id}` ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      t('config.revert')
                    )}
                  </button>
                )}
              </li>
            )
          })}
        </ul>
      </section>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="space-y-4">
          <section
            className="rounded-2xl p-4"
            style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
          >
            <div className="flex items-center gap-2">
              <ExternalLink className="h-4 w-4 text-amber-400" />
              <h3 className="text-[13px] font-semibold text-zinc-100">{t('config.panelsTitle')}</h3>
            </div>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('config.panelsDescription')}</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {catalog.legacyPanels.map((panel) => (
                <button
                  key={panel.id}
                  type="button"
                  disabled={busy}
                  onClick={() => void launchPanel(panel.id)}
                  className="rounded-xl px-3 py-3 text-left transition-colors hover:bg-white/[0.02] disabled:opacity-40"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)' }}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="text-[12px] font-medium text-zinc-200">{panel.name}</span>
                    {runningId === `panel:${panel.id}` ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin text-amber-400" />
                    ) : (
                      <ExternalLink className="h-3.5 w-3.5" style={{ color: 'var(--text-muted)' }} />
                    )}
                  </span>
                  <span className="mt-1 block text-[11px]" style={{ color: 'var(--text-muted)' }}>{panel.description}</span>
                </button>
              ))}
            </div>
          </section>

          <section
            className="rounded-2xl p-4"
            style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
          >
            <div className="flex items-center gap-2">
              <Wrench className="h-4 w-4 text-amber-400" />
              <h3 className="text-[13px] font-semibold text-zinc-100">{t('config.fixesTitle')}</h3>
            </div>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('config.fixesDescription')}</p>
            {runningId?.startsWith('fix:') && (
              <div className="mt-3 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                <UtilityProgressBar progress={progress} fallback={t('config.running')} />
              </div>
            )}
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {catalog.fixes.map((fix) => (
                <div
                  key={fix.id}
                  className="rounded-xl p-3"
                  style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-default)' }}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="text-[12px] font-semibold text-zinc-200">{fix.name}</h4>
                    {renderAdminBadge(fix.requiresAdmin)}
                    {renderRebootBadge(fix.requiresReboot)}
                  </div>
                  <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>{fix.description}</p>
                  {fix.notes && <p className="mt-2 text-[10px] text-amber-200">{fix.notes}</p>}
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void runFix(fix)}
                    className="mt-3 flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--accent)', color: 'white' }}
                  >
                    {runningId === `fix:${fix.id}` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wrench className="h-3.5 w-3.5" />}
                    {t('config.runFix')}
                  </button>
                </div>
              ))}
            </div>
          </section>
        </div>

        <aside>
          <section
            className="rounded-2xl p-4"
            style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
          >
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-amber-400" />
              <h3 className="text-[13px] font-semibold text-zinc-100">{t('config.openSshTitle')}</h3>
            </div>
            <p className="mt-1 text-[11px]" style={{ color: 'var(--text-muted)' }}>
              {catalog.openSsh?.description ?? t('config.openSshUnavailable')}
            </p>
            {catalog.openSsh && (
              <>
                <div className="mt-3 space-y-2 text-[11px]">
                  <div className="flex items-center justify-between gap-3">
                    <span style={{ color: 'var(--text-muted)' }}>{t('config.openSshInstalled')}</span>
                    <span className={openSshStatus?.installed ? 'text-green-400' : 'text-zinc-500'}>
                      {openSshStatus?.installed ? t('config.yes') : t('config.no')}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span style={{ color: 'var(--text-muted)' }}>{t('config.openSshRunning')}</span>
                    <span className={openSshStatus?.serviceRunning ? 'text-green-400' : 'text-zinc-500'}>
                      {openSshStatus?.serviceRunning ? t('config.yes') : t('config.no')}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span style={{ color: 'var(--text-muted)' }}>{t('config.openSshStartup')}</span>
                    <span className="text-zinc-300">{openSshStatus?.startupType ?? t('config.unknown')}</span>
                  </div>
                </div>
                {openSshStatus?.details && (
                  <p className="mt-3 text-[10px]" style={{ color: 'var(--text-faint)' }}>{openSshStatus.details}</p>
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void enableOpenSsh()}
                    className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--accent)', color: 'white' }}
                  >
                    {runningId === 'openssh' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Server className="h-3.5 w-3.5" />}
                    {t('config.enableOpenSsh')}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void loadOpenSshStatus(true)}
                    className="flex items-center gap-1.5 rounded-lg px-3 py-2 text-[12px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border-default)' }}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {t('config.refreshStatus')}
                  </button>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {renderAdminBadge(catalog.openSsh.requiresAdmin)}
                </div>
              </>
            )}
          </section>
        </aside>
      </div>
    </div>
  )
}

export function UtilityTabsPage() {
  const { t } = useTranslation('utilities')
  const { features } = usePlatform()
  const [activeTab, setActiveTab] = useState<'install' | 'tweaks' | 'config'>('install')

  if (!features.utilityTabs) {
    return (
      <div className="animate-fade-in">
        <PageHeader title={t('pageTitle')} description={t('pageDescription')} />
        <EmptyState
          icon={AlertTriangle}
          title="Windows only"
          description="Utility Tabs require Windows (WinGet / system features)."
        />
      </div>
    )
  }

  return (
    <div className="animate-fade-in">
      <PageHeader title={t('pageTitle')} description={t('pageDescription')} />

      <div
        className="mb-6 flex rounded-xl p-1"
        style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      >
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id
          const TabIcon = tab.icon
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex flex-1 items-center justify-center gap-2.5 rounded-lg px-4 py-3 text-[13px] font-medium transition-all',
                isActive ? 'text-amber-400' : 'text-zinc-500 hover:text-zinc-300',
              )}
              style={isActive ? { background: 'var(--accent-muted-bg)' } : undefined}
            >
              <TabIcon className="h-4 w-4 shrink-0" strokeWidth={isActive ? 2.2 : 1.8} />
              <span>{t(tab.labelKey)}</span>
              <span className="hidden text-[11px] sm:inline" style={{ color: isActive ? 'var(--text-dim)' : 'var(--text-muted)' }}>
                {t(tab.descriptionKey)}
              </span>
            </button>
          )
        })}
      </div>

      {activeTab === 'install' && <InstallTab />}
      {activeTab === 'tweaks' && <TweaksTab />}
      {activeTab === 'config' && <ConfigTab />}
    </div>
  )
}
