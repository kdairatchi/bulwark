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

function reportActionResult(t: (k: string, o?: Record<string, unknown>) => string, result: UtilityInstallActionResult) {
  if (result.succeeded > 0) toast.success(t('install.toastSuccess', { count: result.succeeded }))
  if (result.failed > 0) {
    const detail = result.errors.slice(0, 3).map((e) => `${e.id}: ${e.reason}`).join('\n')
    toast.error(t('install.toastFailed', { count: result.failed }), { description: detail || undefined })
  }
}

function InstallTab() {
  const { t } = useTranslation('utilities')
  const searchRef = useRef<HTMLInputElement>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [progressMsg, setProgressMsg] = useState('')
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
      setProgressMsg(p.message)
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

  const runInstallOrUpgrade = async () => {
    if (selected.size === 0) {
      toast.error(t('install.toastNothingSelected'))
      return
    }
    setRunning(true)
    setProgressMsg('')
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
      setProgressMsg('')
    }
  }

  const runUninstall = async () => {
    if (selected.size === 0) {
      toast.error(t('install.toastNothingSelected'))
      return
    }
    setRunning(true)
    setProgressMsg('')
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
      setProgressMsg('')
    }
  }

  const runUpgradeAll = async () => {
    setRunning(true)
    setProgressMsg('')
    try {
      const result = await window.kudu.utilityInstallUpgradeAll()
      reportActionResult(t, result)
      await load(true)
    } catch {
      toast.error(t('install.toastFailed', { count: 1 }))
    } finally {
      setRunning(false)
      setProgressMsg('')
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

      <div className="flex items-center justify-between text-[11px]" style={{ color: 'var(--text-muted)' }}>
        <span>{t('install.selectedCount', { count: selected.size })}</span>
        {running && (
          <span className="flex items-center gap-1.5 text-amber-400">
            <Loader2 className="h-3 w-3 animate-spin" />
            {progressMsg || t('install.running')}
          </span>
        )}
      </div>

      {grouped.length === 0 ? (
        <p className="text-[13px] py-8 text-center" style={{ color: 'var(--text-muted)' }}>{t('install.noMatches')}</p>
      ) : (
        <div className="space-y-4">
          {grouped.map(([category, list]) => (
            <div
              key={category}
              className="rounded-2xl overflow-hidden"
              style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
            >
              <div
                className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider"
                style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-default)' }}
              >
                {t(`install.categories.${category}`, { defaultValue: category })}
              </div>
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
          ))}
        </div>
      )}
    </div>
  )
}

function ComingSoon({ titleKey, descriptionKey }: { titleKey: string; descriptionKey: string }) {
  const { t } = useTranslation('utilities')
  return (
    <EmptyState
      icon={SlidersHorizontal}
      title={t(titleKey)}
      description={t(descriptionKey)}
    />
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
      {activeTab === 'tweaks' && (
        <ComingSoon titleKey="tweaks.comingSoonTitle" descriptionKey="tweaks.comingSoonDescription" />
      )}
      {activeTab === 'config' && (
        <ComingSoon titleKey="config.comingSoonTitle" descriptionKey="config.comingSoonDescription" />
      )}
    </div>
  )
}
