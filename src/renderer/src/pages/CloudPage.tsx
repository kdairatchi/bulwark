import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Cloud,
  Shield,
  ShieldAlert,
  Radar,
  Bug,
  Sparkles,
  MonitorSmartphone,
  Activity,
  FileSearch,
  Bell,
  RefreshCw,
  ExternalLink,
  Link,
  Unlink,
  Check,
  Crown,
  Lock,
  Unlock,
  Radio,
  Download,
  FolderLock,
  Mail,
  type LucideIcon,
} from 'lucide-react'
import { toast } from 'sonner'
import { openPublicCloudDashboard } from '@/lib/cloud-dashboard-url'
import { PageHeader } from '@/components/layout/PageHeader'
import { cn } from '@/lib/utils'
import { useSettingsStore } from '@/stores/settings-store'
import { usePlatform } from '@/hooks/usePlatform'
import type { KuduSettings } from '@shared/types'

export function CloudPage() {
  const { t } = useTranslation('cloud')
  const { features, platform } = usePlatform()
  const { settings, updateSettings, setSettings } = useSettingsStore()

  const [cloudStatus, setCloudStatus] = useState<{
    status: string; maskedApiKey: string | null; deviceId: string | null
    linkedAt: string | null; lastTelemetryAt: string | null; lastHealthReportAt: string | null; error: string | null
    threatBlacklist: { version: string; updatedAt: string; domains: number; ips: number; cidrs: number } | null
  } | null>(null)
  const [cloudApiKey, setCloudApiKey] = useState('')
  const [cloudLinking, setCloudLinking] = useState(false)
  const [cloudUnlinking, setCloudUnlinking] = useState(false)
  const [cloudReconnecting, setCloudReconnecting] = useState(false)
  const [cveSummary, setCveSummary] = useState<{ total: number; critical: number; high: number; medium: number; low: number; librarySize: number } | null>(null)
  const [pairingCode, setPairingCode] = useState('')
  const [pairingBaseUrl, setPairingBaseUrl] = useState('http://127.0.0.1:8787')
  const [pairingEnrolling, setPairingEnrolling] = useState(false)
  const [deviceApiStatus, setDeviceApiStatus] = useState<{
    enrolled: boolean
    running: boolean
    deviceId: string | null
    name: string | null
    baseUrl: string | null
    lastHeartbeatAt: string | null
    lastCommandAt: string | null
    lastCommandType: string | null
    lastError: string | null
    commandsProcessed: number
  } | null>(null)

  const isLinked = !!settings.cloud.apiKey

  const refreshCloudStatus = useCallback(() => {
    window.kudu?.cloudGetStatus?.().then(setCloudStatus).catch(() => {})
  }, [])

  const refreshDeviceApiStatus = useCallback(() => {
    window.kudu?.deviceApiGetStatus?.().then(setDeviceApiStatus).catch(() => {})
  }, [])

  useEffect(() => { window.kudu?.settingsGet?.().then(setSettings).catch(() => {}) }, [])

  useEffect(() => {
    refreshDeviceApiStatus()
    const timer = setInterval(refreshDeviceApiStatus, 5000)
    return () => clearInterval(timer)
  }, [refreshDeviceApiStatus])

  useEffect(() => {
    if (!isLinked) { setCloudStatus(null); setCveSummary(null); return }
    refreshCloudStatus()
    const timer = setInterval(refreshCloudStatus, 5000)
    return () => clearInterval(timer)
  }, [isLinked, refreshCloudStatus])

  useEffect(() => {
    if (cloudStatus?.status !== 'connected') return
    window.kudu?.cveFetch?.({ page: 1 })
      .then((r) => setCveSummary({ total: r.total, librarySize: r.librarySize, ...r.summary }))
      .catch(() => {})
  }, [cloudStatus?.status])

  const handleCloudLink = async () => {
    if (!cloudApiKey.trim() || cloudApiKey.length < 10) return
    setCloudLinking(true)
    try {
      const result = await window.kudu?.cloudLink?.(cloudApiKey.trim())
      if (result?.success) {
        setCloudApiKey('')
        toast.success(t('deviceLinkedToast'))
        const fresh = await window.kudu?.settingsGet?.()
        if (fresh) setSettings(fresh)
      } else {
        toast.error(t('linkFailedToast'), { description: result?.error || t('linkFailedDefaultDesc') })
      }
    } catch {
      toast.error(t('linkFailedToast'), { description: t('linkFailedConnectionDesc') })
    }
    setCloudLinking(false)
  }

  const handleCloudUnlink = async () => {
    setCloudUnlinking(true)
    try {
      await window.kudu?.cloudUnlink?.()
      toast.success(t('deviceUnlinkedToast'))
      const fresh = await window.kudu?.settingsGet?.()
      if (fresh) setSettings(fresh)
    } catch {
      toast.error(t('unlinkFailedToast'))
    }
    setCloudUnlinking(false)
  }

  const handleCloudReconnect = async () => {
    setCloudReconnecting(true)
    try {
      await window.kudu?.cloudReconnect?.()
      refreshCloudStatus()
    } catch {
      toast.error(t('reconnectFailedToast'), { description: t('reconnectFailedDesc') })
    }
    setCloudReconnecting(false)
  }

  const handleDeviceApiEnroll = async () => {
    if (!pairingCode.trim()) return
    setPairingEnrolling(true)
    try {
      const result = await window.kudu?.deviceApiEnroll?.({
        code: pairingCode.trim(),
        baseUrl: pairingBaseUrl.trim() || undefined,
      })
      if (result?.success) {
        setPairingCode('')
        toast.success(t('pairingEnrolledToast'), { description: result.deviceId })
        refreshDeviceApiStatus()
      } else {
        toast.error(t('pairingFailedToast'), { description: result?.error || t('pairingFailedDefaultDesc') })
      }
    } catch {
      toast.error(t('pairingFailedToast'), { description: t('pairingFailedConnectionDesc') })
    }
    setPairingEnrolling(false)
  }

  const handleDeviceApiUnenroll = async () => {
    try {
      await window.kudu?.deviceApiUnenroll?.()
      toast.success(t('pairingUnenrolledToast'))
      refreshDeviceApiStatus()
    } catch {
      toast.error(t('pairingUnenrollFailedToast'))
    }
  }

  const handleDeviceApiPollNow = async () => {
    try {
      const status = await window.kudu?.deviceApiPollNow?.()
      if (status) setDeviceApiStatus(status)
      toast.success(t('pairingPolledToast'))
    } catch {
      toast.error(t('pairingPollFailedToast'))
    }
  }

  const save = (partial: Partial<typeof settings>) => {
    updateSettings(partial)
    window.kudu?.settingsSet?.(partial).catch(() => {})
  }

  const selectStyle = "rounded-lg px-3 py-1.5 text-[13px] text-zinc-400 outline-none"
  const selectBorder = { background: 'var(--bg-subtle-2)', border: '1px solid var(--border-medium)' }

  if (isLinked) {
    return (
      <div className="animate-fade-in max-w-4xl">
        <PageHeader title={t('pageTitle')} description={t('pageDescriptionLinked')} />
        <LinkedCloudSettings
          t={t}
          settings={settings}
          cloudStatus={cloudStatus}
          cveSummary={cveSummary}
          cloudReconnecting={cloudReconnecting}
          cloudUnlinking={cloudUnlinking}
          features={features}
          platform={platform}
          selectStyle={selectStyle}
          selectBorder={selectBorder}
          onReconnect={handleCloudReconnect}
          onUnlink={handleCloudUnlink}
          onSave={save}
        />
        <DeviceApiPairingCard
          t={t}
          status={deviceApiStatus}
          pairingCode={pairingCode}
          pairingBaseUrl={pairingBaseUrl}
          pairingEnrolling={pairingEnrolling}
          onCodeChange={setPairingCode}
          onBaseUrlChange={setPairingBaseUrl}
          onEnroll={handleDeviceApiEnroll}
          onUnenroll={handleDeviceApiUnenroll}
          onPollNow={handleDeviceApiPollNow}
        />
        <ParentControlPanel t={t} baseUrl={pairingBaseUrl} onBaseUrlChange={setPairingBaseUrl} />
      </div>
    )
  }

  return (
    <div className="animate-fade-in max-w-4xl">
      <PageHeader title={t('pageTitle')} description={t('pageDescription')} />

      {/* Hero */}
      <div
        className="relative overflow-hidden rounded-2xl p-8 mb-8"
        style={{
          background: 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(245,158,11,0.02) 50%, rgba(59,130,246,0.06) 100%)',
          border: '1px solid var(--accent-muted-border)',
        }}
      >
        <div className="absolute -right-12 -top-12 h-48 w-48 rounded-full opacity-[0.07]" style={{ background: 'radial-gradient(circle, #f59e0b 0%, transparent 70%)' }} />
        <div className="absolute -left-8 -bottom-8 h-32 w-32 rounded-full opacity-[0.05]" style={{ background: 'radial-gradient(circle, #3b82f6 0%, transparent 70%)' }} />
        <div className="relative">
          <div className="flex items-center gap-3 mb-4">
            <div
              className="flex h-12 w-12 items-center justify-center rounded-2xl"
              style={{ background: 'linear-gradient(135deg, #f59e0b, #d97706)', boxShadow: '0 0 24px rgba(245,158,11,0.25)' }}
            >
              <Cloud className="h-6 w-6 text-black" strokeWidth={2} />
            </div>
            <div>
              <h2 className="text-[18px] font-bold text-white">{t('heroTitle')}</h2>
              <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('heroSubtitle')}</p>
            </div>
          </div>
          <p className="text-[13px] leading-relaxed max-w-xl mb-5" style={{ color: 'var(--text-secondary)' }}>
            {t('heroDescription')}
          </p>
          <button
onClick={() => {
              openPublicCloudDashboard('', () => {
                toast.message(t('cloudDashboardNotConfigured', {
                  defaultValue: 'No public cloud dashboard URL is configured yet. Domain stays open — use device pairing below, or set VITE_BULWRK_CLOUD_URL when you have a host.',
                }))
              })
            }}
            className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-[13px] font-medium transition-all"
            style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
          >
            <ExternalLink className="h-3.5 w-3.5" strokeWidth={1.8} />
            {t('signUpFree')}
          </button>
        </div>
      </div>

      {/* Local features unlocked */}
      <SectionHeading title={t('localFeaturesTitle')} subtitle={t('localFeaturesSubtitle')} />
      <div className="grid grid-cols-2 gap-3 mb-4">
        <FeatureCard
          icon={ShieldAlert}
          title={t('featureThreatMonitorTitle')}
          description={t('featureThreatMonitorDesc')}
          color="#22c55e"
          tier="pro"
        />
        <FeatureCard
          icon={Bug}
          title={t('featureVulnerabilityTitle')}
          description={t('featureVulnerabilityDesc')}
          color="#ef4444"
          tier="pro"
        />
        <FeatureCard
          icon={Sparkles}
          title={t('featureAiSafetyTitle')}
          description={t('featureAiSafetyDesc')}
          color="#f59e0b"
          tier="basic"
        />
        <FeatureCard
          icon={Shield}
          title={t('featureBreachMonitorTitle')}
          description={t('featureBreachMonitorDesc')}
          color="#3b82f6"
          tier="basic"
        />
        <FeatureCard
          icon={Radar}
          title={t('featureHealthReportsTitle')}
          description={t('featureHealthReportsDesc')}
          color="#8b5cf6"
        />
      </div>
      <p className="text-[12px] mb-10 leading-relaxed" style={{ color: 'var(--text-dim)' }}>
        {t('localFeaturesNote')}
      </p>

      {/* Cloud dashboard features */}
      <SectionHeading title={t('cloudFeaturesTitle')} subtitle={t('cloudFeaturesSubtitle')} />
      <div className="grid grid-cols-2 gap-3 mb-10">
        <FeatureCard
          icon={MonitorSmartphone}
          title={t('featureRemoteTitle')}
          description={t('featureRemoteDesc')}
          color="#8b5cf6"
        />
        <FeatureCard
          icon={Activity}
          title={t('featureTelemetryTitle')}
          description={t('featureTelemetryDesc')}
          color="#06b6d4"
        />
        <FeatureCard
          icon={FileSearch}
          title={t('featureComplianceTitle')}
          description={t('featureComplianceDesc')}
          color="#10b981"
        />
        <FeatureCard
          icon={Bell}
          title={t('featureAlertsTitle')}
          description={t('featureAlertsDesc')}
          color="#f97316"
          tier="pro"
        />
      </div>

      {/* Upgrade callout */}
      <div
        className="rounded-2xl p-5 mb-10 flex items-start gap-4"
        style={{ background: 'linear-gradient(135deg, rgba(59,130,246,0.06) 0%, rgba(139,92,246,0.06) 100%)', border: '1px solid rgba(59,130,246,0.12)' }}
      >
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl mt-0.5"
          style={{ background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.2)' }}
        >
          <Crown className="h-[18px] w-[18px] text-blue-400" strokeWidth={1.8} />
        </div>
        <div>
          <h4 className="text-[13px] font-semibold text-zinc-200 mb-1">{t('upgradeCalloutTitle')}</h4>
          <p className="text-[12px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
            {t('upgradeCalloutDesc')}
          </p>
        </div>
      </div>

      {/* Plans */}
      <SectionHeading title={t('plansTitle')} subtitle={t('plansSubtitle')} />
      <div className="grid grid-cols-2 gap-3 mb-10">
        <PlanCard
          name={t('planBasicName')}
          price={t('planBasicPrice')}
          period={t('planBasicPeriod')}
          features={[
            t('planBasicFeature1'),
            t('planBasicFeature2'),
            t('planBasicFeature3'),
            t('planBasicFeature4'),
            t('planBasicFeature5'),
            t('planBasicFeature6'),
          ]}
          highlight={false}
          badge={t('planPopularBadge')}
        />
        <PlanCard
          name={t('planProName')}
          price={t('planProPrice')}
          period={t('planProPeriod')}
          features={[
            t('planProFeature1'),
            t('planProFeature2'),
            t('planProFeature3'),
            t('planProFeature4'),
            t('planProFeature5'),
            t('planProFeature6'),
            t('planProFeature7'),
          ]}
          highlight
        />
      </div>

      {/* Connect section */}
      <div
        className="rounded-2xl p-6 mb-4"
        style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      >
        <h3 className="text-[15px] font-semibold text-white mb-1">{t('connectTitle')}</h3>
        <p className="text-[12px] mb-5" style={{ color: 'var(--text-muted)' }}>{t('connectDescription')}</p>

        <div className="flex gap-3 mb-4">
          <button
onClick={() => {
              openPublicCloudDashboard('', () => {
                toast.message(t('cloudDashboardNotConfigured', {
                  defaultValue: 'No public cloud dashboard URL is configured yet. Domain stays open — use device pairing below, or set VITE_BULWRK_CLOUD_URL when you have a host.',
                }))
              })
            }}
            className="flex items-center gap-2 rounded-xl px-5 py-3 text-[13px] font-medium transition-all"
            style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
          >
            <ExternalLink className="h-3.5 w-3.5" strokeWidth={1.8} />
            {t('signUpFree')}
          </button>
        </div>

        <p className="text-[13px] mb-3" style={{ color: 'var(--text-muted)' }}>{t('alreadyHaveAccount')}</p>
        <div className="flex items-center gap-2.5">
          <input
            type="text"
            value={cloudApiKey}
            onChange={(e) => setCloudApiKey(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCloudLink()}
            placeholder={t('apiKeyPlaceholder')}
            className="flex-1 rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
          />
          <button
            onClick={handleCloudLink}
            disabled={cloudLinking || cloudApiKey.length < 10}
            className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium transition-colors disabled:opacity-40"
            style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
          >
            <Link className="h-3.5 w-3.5" strokeWidth={1.8} />
            {cloudLinking ? t('linking') : t('linkDevice')}
          </button>
        </div>
        <p className="mt-3 text-[11px]" style={{ color: 'var(--text-dim)' }}>
          {t('telemetryDisclaimer', { registryExtra: features.registry ? t('telemetryRegistryExtra') : '' })}
        </p>
      </div>

      {/* Device API pairing (Ed25519 — preferred Bulwrk path) */}
      <DeviceApiPairingCard
        t={t}
        status={deviceApiStatus}
        pairingCode={pairingCode}
        pairingBaseUrl={pairingBaseUrl}
        pairingEnrolling={pairingEnrolling}
        onCodeChange={setPairingCode}
        onBaseUrlChange={setPairingBaseUrl}
        onEnroll={handleDeviceApiEnroll}
        onUnenroll={handleDeviceApiUnenroll}
        onPollNow={handleDeviceApiPollNow}
      />
      <ParentControlPanel t={t} baseUrl={pairingBaseUrl} onBaseUrlChange={setPairingBaseUrl} />
    </div>
  )
}

/* ── Sub-components ─────────────────────────────────────────── */

type ParentDevice = {
  id: string
  name: string
  os: string | null
  enrolledAt: string
  lastHeartbeat: string | null
  inventoryCount: number
  findingsCount: number
  openFindingsCount?: number
  securityScore?: number
  isolated: boolean
  policyVersion: number
  dnsGuardRequired: boolean
  blockedDomains: string[]
  dnsGuardRunning?: boolean
  vpnConsentPending?: boolean
}

type ParentEvent = {
  id: string
  deviceId: string
  type: string
  at: string
  subject: string | null
  detail: string | null
}

type ParentFinding = {
  id: string
  deviceId: string
  level: string
  subjectName: string
  reason: string
  category?: string | null
  fixRecommendation?: string | null
  createdAt: string
  updatedAt?: string | null
  status?: string
  reviewedAt?: string | null
  reviewNote?: string | null
}

type ParentBreachEntry = {
  id: string
  name: string
  title: string
  domain: string
  breachDate: string
  dataClasses: string[]
  pwnCount: number
  isVerified: boolean
  isSensitive: boolean
  acknowledgedAt: string | null
}

type ParentMonitoredEmail = {
  email: string
  lastCheckedAt: string | null
  fresh: boolean
  monitoringPaused: boolean
  breaches: ParentBreachEntry[]
}

function ParentControlPanel({
  t, baseUrl, onBaseUrlChange,
}: {
  t: (key: string) => string
  baseUrl: string
  onBaseUrlChange: (v: string) => void
}) {
  const [devices, setDevices] = useState<ParentDevice[]>([])
  const [events, setEvents] = useState<ParentEvent[]>([])
  const [findings, setFindings] = useState<ParentFinding[]>([])
  const [breachEmails, setBreachEmails] = useState<ParentMonitoredEmail[]>([])
  const [breachUsage, setBreachUsage] = useState(0)
  const [breachLimit, setBreachLimit] = useState(10)
  const [breachEmailInput, setBreachEmailInput] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [minting, setMinting] = useState(false)
  const [mintedCode, setMintedCode] = useState<string | null>(null)
  const [blockedText, setBlockedText] = useState('')
  const [quarantinePath, setQuarantinePath] = useState('')
  const [vulnOsv, setVulnOsv] = useState(false)
  const [findingCategoryFilter, setFindingCategoryFilter] = useState<string>('all')
  const [dnsGuard, setDnsGuard] = useState(false)
  const [busy, setBusy] = useState(false)
  const [dashboardToken, setDashboardToken] = useState('')

  const selected = devices.find((d) => d.id === selectedId) ?? null

  const authPayload = useCallback(() => ({
    baseUrl: baseUrl.trim() || undefined,
    token: dashboardToken.trim() || undefined,
  }), [baseUrl, dashboardToken])

  const ensureToken = useCallback(async (): Promise<string> => {
    if (dashboardToken.trim()) return dashboardToken.trim()
    try {
      const res = await window.kudu?.dashboardBootstrap?.({ baseUrl: baseUrl.trim() || undefined })
      if (res?.success && res.token) {
        setDashboardToken(res.token)
        return res.token
      }
    } catch { /* ignore */ }
    return ''
  }, [baseUrl, dashboardToken])

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const token = await ensureToken()
      const base = { baseUrl: baseUrl.trim() || undefined, token: token || undefined }
      const [devRes, evtRes, findRes, breachRes] = await Promise.all([
        window.kudu?.dashboardListDevices?.(base),
        window.kudu?.dashboardListEvents?.({
          ...base,
          deviceId: selectedId || undefined,
        }),
        window.kudu?.dashboardListFindings?.({
          ...base,
          deviceId: selectedId || undefined,
        }),
        window.kudu?.dashboardListBreachMonitors?.(base),
      ])
      if (devRes?.success) {
        setDevices(devRes.devices)
        if (selectedId && !devRes.devices.some((d) => d.id === selectedId)) {
          setSelectedId(devRes.devices[0]?.id ?? null)
        } else if (!selectedId && devRes.devices[0]) {
          setSelectedId(devRes.devices[0].id)
        }
      } else if (devRes && !devRes.success) {
        toast.error(t('parentLoadFailedToast'), { description: devRes.error })
      }
      if (evtRes?.success) setEvents(evtRes.events)
      if (findRes?.success) setFindings(findRes.findings)
      if (breachRes?.success) {
        setBreachEmails(breachRes.emails)
        setBreachUsage(breachRes.usage)
        setBreachLimit(breachRes.limit)
      }
    } catch {
      toast.error(t('parentLoadFailedToast'))
    }
    setLoading(false)
  }, [baseUrl, selectedId, t, ensureToken])

  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 8000)
    return () => clearInterval(timer)
  }, [refresh])

  useEffect(() => {
    if (!selected) return
    setBlockedText(selected.blockedDomains.join('\n'))
    setDnsGuard(selected.dnsGuardRequired)
  }, [selected?.id, selected?.policyVersion])

  const handleMint = async () => {
    setMinting(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardCreatePairingCode?.({
        ...authPayload(),
        token: token || undefined,
      })
      if (res?.success) {
        setMintedCode(res.code)
        toast.success(t('parentMintedToast'), { description: res.code })
      } else {
        toast.error(t('parentMintFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentMintFailedToast'))
    }
    setMinting(false)
  }

  const handleIsolate = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardIsolate?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        reason: 'parent emergency isolate',
      })
      if (res?.success) {
        toast.success(t('parentIsolatedToast'))
        await refresh()
      } else {
        toast.error(t('parentIsolateFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentIsolateFailedToast'))
    }
    setBusy(false)
  }

  const handleClear = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardClearIsolation?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
      })
      if (res?.success) {
        toast.success(t('parentClearedToast'))
        await refresh()
      } else {
        toast.error(t('parentIsolateFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentIsolateFailedToast'))
    }
    setBusy(false)
  }

  const handleSavePolicy = async () => {
    if (!selected) return
    setBusy(true)
    const blockedDomains = blockedText.split(/[\n,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardPutPolicy?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        blockedDomains,
        dnsGuardRequired: dnsGuard,
      })
      if (res?.success) {
        toast.success(t('parentPolicySavedToast'))
        await refresh()
      } else {
        toast.error(t('parentPolicyFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentPolicyFailedToast'))
    }
    setBusy(false)
  }

  const handleRequestInventory = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardIssueCommand?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        type: 'REQUEST_INVENTORY',
      })
      if (res?.success) {
        toast.success(t('parentInventoryQueuedToast'))
        await refresh()
      } else {
        toast.error(t('parentInventoryFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentInventoryFailedToast'))
    }
    setBusy(false)
  }

  const handleRequestScan = async (
    kind: 'health' | 'malware' | 'vulnerability' | 'lolbins',
    extra: Record<string, unknown> = {},
  ) => {
    if (!selected) return
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardRequestScan?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        kind,
        scope: kind === 'malware' ? 'quick' : kind === 'lolbins' ? 'lolbins' : undefined,
        ...(kind === 'vulnerability'
          ? {
              // Phase 5 thin slice: refresh CISA KEV + EPSS; OSV opt-in via checkbox
              kevSync: true,
              epss: true,
              osv: vulnOsv,
              ...extra,
            }
          : extra),
      })
      if (res?.success) {
        toast.success(t('parentScanQueuedToast'), { description: res.command.type })
        await refresh()
      } else {
        toast.error(t('parentScanFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentScanFailedToast'))
    }
    setBusy(false)
  }

  const handleRefreshFeeds = async () => {
    if (!selected) return
    setBusy(true)
    try {
      const token = await ensureToken()
      const extraDomains = blockedText
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 50)
      const res = await window.kudu?.dashboardIssueCommand?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        type: 'UPDATE_THREAT_FEEDS',
        parameters: {
          syncLists: true,
          ...(extraDomains.length ? { domains: extraDomains } : {}),
        },
      })
      if (res?.success) {
        toast.success(t('parentFeedsQueuedToast'))
        await refresh()
      } else {
        toast.error(t('parentFeedsFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentFeedsFailedToast'))
    }
    setBusy(false)
  }

  const handleQuarantineFile = async () => {
    if (!selected) return
    const path = quarantinePath.trim()
    if (!path) {
      toast.error(t('parentQuarantinePathRequired'))
      return
    }
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardIssueCommand?.({
        ...authPayload(),
        token: token || undefined,
        deviceId: selected.id,
        type: 'QUARANTINE_FILE',
        parameters: { path },
      })
      if (res?.success) {
        toast.success(t('parentQuarantineQueuedToast'))
        await refresh()
      } else {
        toast.error(t('parentQuarantineFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentQuarantineFailedToast'))
    }
    setBusy(false)
  }

  const handleReviewFinding = async (findingId: string, status: 'false_positive' | 'accepted_risk') => {
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardReviewFinding?.({
        ...authPayload(),
        token: token || undefined,
        findingId,
        status,
      })
      if (res?.success) {
        toast.success(t('parentReviewToast'), {
          description: `${status} · score ${res.securityScore}`,
        })
        await refresh()
      } else {
        toast.error(t('parentReviewFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentReviewFailedToast'))
    }
    setBusy(false)
  }

  const handleAddBreachMonitor = async () => {
    const email = breachEmailInput.trim()
    if (!email) {
      toast.error(t('parentBreachEmailRequired'))
      return
    }
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardCreateBreachMonitor?.({
        ...authPayload(),
        token: token || undefined,
        email,
      })
      if (res?.success) {
        setBreachEmails(res.emails)
        setBreachUsage(res.usage)
        setBreachLimit(res.limit)
        setBreachEmailInput('')
        toast.success(t('parentBreachAddedToast'), {
          description: res.source ? `source=${res.source}` : undefined,
        })
      } else {
        toast.error(t('parentBreachAddFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentBreachAddFailedToast'))
    }
    setBusy(false)
  }

  const handleRemoveBreachMonitor = async (email: string) => {
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardDeleteBreachMonitor?.({
        ...authPayload(),
        token: token || undefined,
        email,
      })
      if (res?.success) {
        toast.success(t('parentBreachRemovedToast'))
        await refresh()
      } else {
        toast.error(t('parentBreachAddFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentBreachAddFailedToast'))
    }
    setBusy(false)
  }

  const handleAckBreach = async (breachId: string) => {
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardAckBreaches?.({
        ...authPayload(),
        token: token || undefined,
        breachIds: [breachId],
      })
      if (res?.success) {
        toast.success(t('parentBreachAckToast'))
        await refresh()
      } else {
        toast.error(t('parentBreachAddFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentBreachAddFailedToast'))
    }
    setBusy(false)
  }

  const handleRefreshBreaches = async () => {
    setBusy(true)
    try {
      const token = await ensureToken()
      const res = await window.kudu?.dashboardRefreshBreachMonitors?.({
        ...authPayload(),
        token: token || undefined,
      })
      if (res?.success) {
        setBreachEmails(res.emails)
        setBreachUsage(res.usage)
        setBreachLimit(res.limit)
        toast.success(t('parentBreachRefreshedToast'), {
          description: res.source ? `source=${res.source}` : undefined,
        })
      } else {
        toast.error(t('parentBreachAddFailedToast'), { description: res && 'error' in res ? res.error : undefined })
      }
    } catch {
      toast.error(t('parentBreachAddFailedToast'))
    }
    setBusy(false)
  }

  return (
    <div
      className="rounded-2xl p-6 mb-4 mt-4"
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
    >
      <div className="flex items-start justify-between gap-3 mb-1">
        <div>
          <h3 className="text-[15px] font-semibold text-white">{t('parentTitle')}</h3>
          <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('parentDescription')}</p>
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-xl px-3 py-2 text-[12px] font-medium disabled:opacity-40"
          style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} strokeWidth={1.8} />
          {t('parentRefresh')}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 mt-4 mb-2">
        <input
          type="text"
          value={baseUrl}
          onChange={(e) => onBaseUrlChange(e.target.value)}
          placeholder={t('pairingBaseUrlPlaceholder')}
          className="flex-1 min-w-[220px] rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700"
          style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
        />
        <button
          onClick={handleMint}
          disabled={minting}
          className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
          style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
        >
          <Radio className="h-3.5 w-3.5" strokeWidth={1.8} />
          {minting ? t('parentCreatingCode') : t('parentCreateCode')}
        </button>
      </div>
      <input
        type="password"
        value={dashboardToken}
        onChange={(e) => setDashboardToken(e.target.value)}
        placeholder={t('parentTokenPlaceholder')}
        className="w-full mb-4 rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700 font-mono"
        style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
      />
      <p className="text-[11px] -mt-3 mb-4" style={{ color: 'var(--text-dim)' }}>{t('parentTokenHint')}</p>

      {mintedCode && (
        <div
          className="mb-4 rounded-xl px-4 py-3 text-[14px] font-mono tracking-widest text-center"
          style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)', color: '#fbbf24' }}
        >
          {mintedCode}
        </div>
      )}

      {devices.length === 0 ? (
        <p className="text-[12px]" style={{ color: 'var(--text-dim)' }}>{t('parentNoDevices')}</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            {devices.map((d) => (
              <button
                key={d.id}
                type="button"
                onClick={() => setSelectedId(d.id)}
                className="w-full text-left rounded-xl px-4 py-3 transition-colors"
                style={{
                  background: selectedId === d.id ? 'rgba(245,158,11,0.08)' : 'var(--bg-subtle)',
                  border: selectedId === d.id ? '1px solid rgba(245,158,11,0.35)' : '1px solid var(--border-medium)',
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[13px] font-medium text-zinc-200">{d.name}</span>
                  <span className="flex flex-wrap gap-1 justify-end">
                    {d.isolated && (
                      <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded" style={{ background: 'rgba(239,68,68,0.15)', color: '#f87171' }}>
                        {t('parentIsolatedBadge')}
                      </span>
                    )}
                    {d.vpnConsentPending && (
                      <span className="text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded" style={{ background: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}>
                        {t('parentVpnPendingBadge')}
                      </span>
                    )}
                  </span>
                </div>
                <div className="text-[11px] mt-1" style={{ color: 'var(--text-muted)' }}>
                  {d.os || 'unknown'} · {t('parentOnline')}: {d.lastHeartbeat ? new Date(d.lastHeartbeat).toLocaleString() : t('parentNever')}
                </div>
                <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-dim)' }}>
                  {t('parentApps')}: {d.inventoryCount} · {t('parentFindings')}: {d.openFindingsCount ?? d.findingsCount}
                  {' · '}
                  <span style={{
                    color: (d.securityScore ?? 100) >= 80 ? '#4ade80'
                      : (d.securityScore ?? 100) >= 50 ? '#fbbf24' : '#f87171',
                  }}>
                    {t('parentScore')}: {d.securityScore ?? '—'}
                  </span>
                </div>
              </button>
            ))}
          </div>

          <div className="space-y-3">
            {selected && (
              <>
                <div className="flex flex-wrap gap-2">
                  {selected.isolated ? (
                    <button
                      onClick={handleClear}
                      disabled={busy}
                      className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                      style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                    >
                      <Unlock className="h-3.5 w-3.5" strokeWidth={1.8} />
                      {t('parentClearIsolation')}
                    </button>
                  ) : (
                    <button
                      onClick={handleIsolate}
                      disabled={busy}
                      className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                      style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.35)', color: '#f87171' }}
                    >
                      <Lock className="h-3.5 w-3.5" strokeWidth={1.8} />
                      {t('parentIsolate')}
                    </button>
                  )}
                  <button
                    onClick={handleRequestInventory}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <FileSearch className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRequestInventory')}
                  </button>
                  <button
                    onClick={() => handleRequestScan('health')}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <Activity className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRunHealth')}
                  </button>
                  <button
                    onClick={() => handleRequestScan('malware')}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <ShieldAlert className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRunMalware')}
                  </button>
                  <button
                    onClick={() => handleRequestScan('lolbins')}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <Radar className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRunLolbins')}
                  </button>
                  <button
                    onClick={() => handleRequestScan('vulnerability')}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <Bug className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRunVuln')}
                  </button>
                  <label className="flex items-center gap-1.5 text-[11px] px-1" style={{ color: 'var(--text-muted)' }}>
                    <input type="checkbox" checked={vulnOsv} onChange={(e) => setVulnOsv(e.target.checked)} />
                    {t('parentVulnOsv')}
                  </label>
                  <button
                    onClick={handleRefreshFeeds}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <Download className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentRefreshFeeds')}
                  </button>
                </div>

                <div className="flex flex-wrap items-end gap-2">
                  <div className="flex-1 min-w-[200px]">
                    <div className="text-[11px] mb-1" style={{ color: 'var(--text-muted)' }}>{t('parentQuarantinePath')}</div>
                    <input
                      value={quarantinePath}
                      onChange={(e) => setQuarantinePath(e.target.value)}
                      placeholder="/tmp/suspicious.bin"
                      className="w-full rounded-xl px-3 py-2 text-[12px] text-zinc-300 outline-none font-mono"
                      style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
                    />
                  </div>
                  <button
                    onClick={handleQuarantineFile}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                  >
                    <FolderLock className="h-3.5 w-3.5" strokeWidth={1.8} />
                    {t('parentQuarantineFile')}
                  </button>
                </div>

                <label className="flex items-center gap-2 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                  <input type="checkbox" checked={dnsGuard} onChange={(e) => setDnsGuard(e.target.checked)} />
                  {t('parentDnsGuard')}
                </label>

                <div>
                  <div className="text-[11px] mb-1" style={{ color: 'var(--text-muted)' }}>{t('parentBlockedDomains')}</div>
                  <textarea
                    value={blockedText}
                    onChange={(e) => setBlockedText(e.target.value)}
                    rows={4}
                    className="w-full rounded-xl px-3 py-2 text-[12px] text-zinc-300 outline-none font-mono"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
                  />
                  <button
                    onClick={handleSavePolicy}
                    disabled={busy}
                    className="mt-2 rounded-xl px-4 py-2 text-[12px] font-medium disabled:opacity-40"
                    style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
                  >
                    {t('parentSavePolicy')}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      <div className="mt-5">
        <h4 className="text-[12px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
          {t('parentFindings')}
        </h4>
        {findings.length === 0 ? (
          <p className="text-[12px]" style={{ color: 'var(--text-dim)' }}>{t('parentNoFindings')}</p>
        ) : (
          <>
            <div className="flex flex-wrap gap-1.5 mb-2">
              {(['all', ...Array.from(new Set(findings.map((f) => f.category || 'uncategorized'))).sort()]).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setFindingCategoryFilter(cat)}
                  className="rounded-lg px-2 py-1 text-[10px] font-medium"
                  style={{
                    background: findingCategoryFilter === cat ? 'var(--accent)' : 'var(--bg-subtle)',
                    color: findingCategoryFilter === cat ? 'var(--text-on-accent)' : 'var(--text-secondary)',
                    border: '1px solid var(--border-medium)',
                  }}
                >
                  {cat === 'all' ? t('parentFindingsFilterAll') : cat}
                </button>
              ))}
            </div>
          <div className="max-h-52 overflow-y-auto space-y-1.5 mb-4">
            {[...findings]
              .filter((f) => findingCategoryFilter === 'all' || (f.category || 'uncategorized') === findingCategoryFilter)
              .reverse()
              .slice(0, 40)
              .map((f) => {
              const resolved = ['false_positive', 'accepted_risk', 'fixed', 'not_exploitable'].includes(f.status || '')
              return (
                <div
                  key={f.id}
                  className="rounded-lg px-3 py-2 text-[11px] font-mono"
                  style={{
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-medium)',
                    color: 'var(--text-secondary)',
                    opacity: resolved ? 0.55 : 1,
                  }}
                >
                  <div>
                    <span style={{ color: f.level.includes('likely') ? '#f87171' : '#fbbf24' }}>{f.level}</span>
                    {f.category && (
                      <>
                        {' · '}
                        <span
                          className="rounded px-1"
                          style={{
                            background: f.category === 'kev' || f.category === 'osv'
                              ? 'rgba(248,113,113,0.15)'
                              : 'rgba(148,163,184,0.12)',
                            color: f.category === 'kev' || f.category === 'osv' ? '#f87171' : 'var(--text-muted)',
                          }}
                        >
                          {f.category}
                        </span>
                      </>
                    )}
                    {' · '}
                    {f.subjectName}
                    {' · '}
                    <span style={{ color: 'var(--text-dim)' }}>{f.reason}</span>
                    {f.status && (
                      <>
                        {' · '}
                        <span style={{ color: resolved ? '#4ade80' : 'var(--text-muted)' }}>{f.status}</span>
                      </>
                    )}
                  </div>
                  {f.fixRecommendation && (
                    <div className="mt-1 text-[10px] font-sans" style={{ color: 'var(--text-muted)' }}>
                      Fix: {f.fixRecommendation}
                    </div>
                  )}
                  {!resolved && (
                    <div className="flex flex-wrap gap-1.5 mt-1.5">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleReviewFinding(f.id, 'false_positive')}
                        className="rounded-lg px-2 py-1 text-[10px] font-sans font-medium disabled:opacity-40"
                        style={{ background: 'var(--bg-elevated, var(--bg-subtle))', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                      >
                        {t('parentMarkFalsePositive')}
                      </button>
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => handleReviewFinding(f.id, 'accepted_risk')}
                        className="rounded-lg px-2 py-1 text-[10px] font-sans font-medium disabled:opacity-40"
                        style={{ background: 'var(--bg-elevated, var(--bg-subtle))', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
                      >
                        {t('parentMarkAcceptedRisk')}
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
          </>
        )}
      </div>

      <div className="mt-4">
        <div className="flex items-center justify-between gap-2 mb-2">
          <h4 className="text-[12px] font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            <Mail className="inline h-3.5 w-3.5 mr-1.5 -mt-0.5" strokeWidth={1.8} />
            {t('parentBreachTitle')}
          </h4>
          <span className="text-[10px] font-mono" style={{ color: 'var(--text-dim)' }}>
            {t('parentBreachUsage', { usage: breachUsage, limit: breachLimit })}
          </span>
        </div>
        <p className="text-[11px] mb-2" style={{ color: 'var(--text-dim)' }}>{t('parentBreachHint')}</p>
        <div className="flex flex-wrap gap-2 mb-3">
          <input
            type="email"
            value={breachEmailInput}
            onChange={(e) => setBreachEmailInput(e.target.value)}
            placeholder={t('parentBreachEmailPlaceholder')}
            className="flex-1 min-w-[180px] rounded-xl px-3 py-2 text-[12px] outline-none"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
            onKeyDown={(e) => { if (e.key === 'Enter') void handleAddBreachMonitor() }}
          />
          <button
            type="button"
            disabled={busy}
            onClick={handleAddBreachMonitor}
            className="rounded-xl px-3 py-2 text-[12px] font-medium disabled:opacity-40"
            style={{ background: 'rgba(96,165,250,0.15)', border: '1px solid rgba(96,165,250,0.35)', color: '#93c5fd' }}
          >
            {t('parentBreachAdd')}
          </button>
          <button
            type="button"
            disabled={busy || breachEmails.length === 0}
            onClick={handleRefreshBreaches}
            className="rounded-xl px-3 py-2 text-[12px] font-medium disabled:opacity-40"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
          >
            {t('parentBreachRefresh')}
          </button>
        </div>
        {breachEmails.length === 0 ? (
          <p className="text-[12px]" style={{ color: 'var(--text-dim)' }}>{t('parentBreachEmpty')}</p>
        ) : (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {breachEmails.map((m) => (
              <div
                key={m.email}
                className="rounded-lg px-3 py-2"
                style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="text-[12px] font-mono" style={{ color: 'var(--text-secondary)' }}>
                    {m.email}
                    <span className="ml-2 text-[10px]" style={{ color: m.fresh ? '#4ade80' : 'var(--text-dim)' }}>
                      {m.fresh ? 'fresh' : 'stale'}
                    </span>
                    <span className="ml-2 text-[10px]" style={{ color: 'var(--text-dim)' }}>
                      {m.breaches.filter((b) => !b.acknowledgedAt).length} open / {m.breaches.length} total
                    </span>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => handleRemoveBreachMonitor(m.email)}
                    className="text-[10px] px-2 py-1 rounded disabled:opacity-40"
                    style={{ border: '1px solid var(--border-medium)', color: 'var(--text-muted)' }}
                  >
                    {t('parentBreachRemove')}
                  </button>
                </div>
                {m.breaches.length > 0 && (
                  <div className="mt-1.5 space-y-1">
                    {m.breaches.slice(0, 8).map((b) => (
                      <div
                        key={b.id}
                        className="flex items-start justify-between gap-2 text-[11px]"
                        style={{ color: b.acknowledgedAt ? 'var(--text-dim)' : 'var(--text-secondary)', opacity: b.acknowledgedAt ? 0.55 : 1 }}
                      >
                        <div>
                          <span style={{ color: '#f87171' }}>{b.title || b.name}</span>
                          {' · '}
                          {b.domain || '—'}
                          {' · '}
                          {b.breachDate}
                          {b.dataClasses?.length > 0 && (
                            <span style={{ color: 'var(--text-dim)' }}> · {b.dataClasses.slice(0, 4).join(', ')}</span>
                          )}
                        </div>
                        {!b.acknowledgedAt && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => handleAckBreach(b.id)}
                            className="shrink-0 text-[10px] px-2 py-0.5 rounded disabled:opacity-40"
                            style={{ border: '1px solid var(--border-medium)', color: 'var(--text-muted)' }}
                          >
                            {t('parentBreachAck')}
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="mt-2">
        <h4 className="text-[12px] font-semibold uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
          {t('parentEvents')}
        </h4>
        {events.length === 0 ? (
          <p className="text-[12px]" style={{ color: 'var(--text-dim)' }}>{t('parentNoEvents')}</p>
        ) : (
          <div className="max-h-48 overflow-y-auto space-y-1.5">
            {[...events].reverse().slice(0, 40).map((e) => (
              <div
                key={e.id}
                className="rounded-lg px-3 py-2 text-[11px] font-mono"
                style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
              >
                <span style={{ color: e.type.includes('block') || e.type.includes('isolat') ? '#f87171' : '#a1a1aa' }}>{e.type}</span>
                {' · '}
                {e.subject || '—'}
                {' · '}
                <span style={{ color: 'var(--text-dim)' }}>{new Date(e.at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function DeviceApiPairingCard({
  t, status, pairingCode, pairingBaseUrl, pairingEnrolling,
  onCodeChange, onBaseUrlChange, onEnroll, onUnenroll, onPollNow,
}: {
  t: (key: string) => string
  status: {
    enrolled: boolean
    deviceId: string | null
    baseUrl: string | null
    lastHeartbeatAt: string | null
    lastCommandAt: string | null
    lastCommandType: string | null
    lastError: string | null
    commandsProcessed: number
  } | null
  pairingCode: string
  pairingBaseUrl: string
  pairingEnrolling: boolean
  onCodeChange: (v: string) => void
  onBaseUrlChange: (v: string) => void
  onEnroll: () => void
  onUnenroll: () => void
  onPollNow: () => void
}) {
  return (
    <div
      className="rounded-2xl p-6 mb-4 mt-4"
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
    >
      <h3 className="text-[15px] font-semibold text-white mb-1">{t('pairingTitle')}</h3>
      <p className="text-[12px] mb-5" style={{ color: 'var(--text-muted)' }}>{t('pairingDescription')}</p>

      {status?.enrolled ? (
        <div className="space-y-3">
          <div className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
            <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingDeviceId')}: </span>{status.deviceId}</div>
            <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingBaseUrl')}: </span>{status.baseUrl}</div>
            <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingHeartbeat')}: </span>{status.lastHeartbeatAt || t('statusLoading')}</div>
            <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingLastCommand')}: </span>
              {status.lastCommandType
                ? `${status.lastCommandType} @ ${status.lastCommandAt}`
                : '—'}
            </div>
            <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingProcessed')}: </span>{status.commandsProcessed}</div>
            {status.lastError && (
              <div className="text-red-400 text-[12px] mt-1">{status.lastError}</div>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={onPollNow}
              className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium"
              style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
            >
              <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.8} />
              {t('pairingPollNow')}
            </button>
            <button
              onClick={onUnenroll}
              className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium"
              style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
            >
              <Unlink className="h-3.5 w-3.5" strokeWidth={1.8} />
              {t('pairingUnenroll')}
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <input
            type="text"
            value={pairingBaseUrl}
            onChange={(e) => onBaseUrlChange(e.target.value)}
            placeholder={t('pairingBaseUrlPlaceholder')}
            className="w-full rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700"
            style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
          />
          <div className="flex items-center gap-2.5">
            <input
              type="text"
              value={pairingCode}
              onChange={(e) => onCodeChange(e.target.value.toUpperCase())}
              onKeyDown={(e) => e.key === 'Enter' && onEnroll()}
              placeholder={t('pairingCodePlaceholder')}
              className="flex-1 rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700 tracking-widest"
              style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
            />
            <button
              onClick={onEnroll}
              disabled={pairingEnrolling || pairingCode.trim().length < 4}
              className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium transition-colors disabled:opacity-40"
              style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
            >
              <Link className="h-3.5 w-3.5" strokeWidth={1.8} />
              {pairingEnrolling ? t('pairingEnrolling') : t('pairingEnroll')}
            </button>
          </div>
          <p className="text-[11px]" style={{ color: 'var(--text-dim)' }}>{t('pairingHint')}</p>
        </div>
      )}
    </div>
  )
}

function SectionHeading({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-4">
      <h3 className="text-[11px] font-medium uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>{title}</h3>
      <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-dim)' }}>{subtitle}</p>
    </div>
  )
}

const TIER_COLORS: Record<string, { bg: string; border: string; text: string }> = {
  basic: { bg: 'rgba(59,130,246,0.12)', border: 'rgba(59,130,246,0.25)', text: '#60a5fa' },
  pro:   { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.25)', text: '#fbbf24' },
}

function FeatureCard({ icon: Icon, title, description, color, tier }: { icon: LucideIcon; title: string; description: string; color: string; tier?: 'basic' | 'pro' }) {
  const tierStyle = tier ? TIER_COLORS[tier] : null
  return (
    <div
      className="group relative rounded-2xl p-5 transition-all duration-300"
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = `${color}22`
        e.currentTarget.style.boxShadow = `0 0 24px ${color}08`
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--border-default)'
        e.currentTarget.style.boxShadow = 'none'
      }}
    >
      {tierStyle && (
        <div
          className="absolute top-3.5 right-3.5 rounded-md px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider"
          style={{ background: tierStyle.bg, border: `1px solid ${tierStyle.border}`, color: tierStyle.text }}
        >
          {tier}
        </div>
      )}
      <div
        className="mb-3 flex h-9 w-9 items-center justify-center rounded-xl"
        style={{ background: `${color}15`, border: `1px solid ${color}20` }}
      >
        <Icon className="h-[18px] w-[18px]" style={{ color }} strokeWidth={1.8} />
      </div>
      <h4 className="text-[13px] font-semibold text-zinc-200 mb-1">{title}</h4>
      <p className="text-[12px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>{description}</p>
    </div>
  )
}

function PlanCard({ name, price, period, features, highlight, badge }: {
  name: string; price: string; period: string; features: string[]; highlight: boolean; badge?: string
}) {
  return (
    <div
      className="relative rounded-2xl p-5 flex flex-col"
      style={{
        background: highlight
          ? 'linear-gradient(180deg, rgba(245,158,11,0.06) 0%, var(--card-bg) 100%)'
          : 'var(--card-bg)',
        border: highlight
          ? '1px solid var(--accent-muted-border)'
          : '1px solid var(--border-default)',
      }}
    >
      {badge && (
        <div
          className="absolute -top-2.5 left-1/2 -translate-x-1/2 rounded-full px-3 py-0.5 text-[10px] font-bold uppercase tracking-wider"
          style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
        >
          {badge}
        </div>
      )}
      {highlight && (
        <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 flex items-center gap-1 rounded-full px-3 py-0.5 text-[10px] font-bold uppercase tracking-wider"
          style={{ background: 'linear-gradient(135deg, #f59e0b, #d97706)', color: '#000' }}
        >
          <Crown className="h-3 w-3" strokeWidth={2.5} />
          PRO
        </div>
      )}
      <div className="mb-4 mt-1">
        <p className="text-[12px] font-medium" style={{ color: 'var(--text-muted)' }}>{name}</p>
        <div className="flex items-baseline gap-1 mt-1">
          <span className="text-[22px] font-bold text-white">{price}</span>
          <span className="text-[11px]" style={{ color: 'var(--text-dim)' }}>{period}</span>
        </div>
      </div>
      <div className="space-y-2.5 flex-1">
        {features.map((f, i) => (
          <div key={i} className="flex items-start gap-2">
            <Check className="h-3.5 w-3.5 mt-0.5 shrink-0" style={{ color: highlight ? '#f59e0b' : '#22c55e' }} strokeWidth={2.5} />
            <span className="text-[12px] leading-snug" style={{ color: 'var(--text-secondary)' }}>{f}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Linked settings (moved from SettingsPage) ────────────── */

function LinkedCloudSettings({ t, settings, cloudStatus, cveSummary, cloudReconnecting, cloudUnlinking, features, platform, selectStyle, selectBorder, onReconnect, onUnlink, onSave }: {
  t: (key: string, opts?: Record<string, unknown>) => string
  settings: KuduSettings
  cloudStatus: {
    status: string; maskedApiKey: string | null; deviceId: string | null
    linkedAt: string | null; lastTelemetryAt: string | null; lastHealthReportAt: string | null; error: string | null
    threatBlacklist: { version: string; updatedAt: string; domains: number; ips: number; cidrs: number } | null
  } | null
  cveSummary: { total: number; critical: number; high: number; medium: number; low: number; librarySize: number } | null
  cloudReconnecting: boolean
  cloudUnlinking: boolean
  features: { registry: boolean; [k: string]: unknown }
  platform: string
  selectStyle: string
  selectBorder: React.CSSProperties
  onReconnect: () => void
  onUnlink: () => void
  onSave: (partial: Partial<KuduSettings>) => void
}) {
  return (
    <>
      <Section title={t('sectionStatus')}>
        <Row label={t('statusLabel')}>
          <div className="flex items-center gap-2">
            <div
              className={cn('h-2.5 w-2.5 rounded-full', cloudStatus?.status === 'connecting' && 'animate-pulse')}
              style={{
                background:
                  cloudStatus?.status === 'connected' ? '#22c55e' :
                  cloudStatus?.status === 'connecting' ? '#f59e0b' :
                  cloudStatus?.status === 'disconnected' ? '#f59e0b' :
                  cloudStatus?.status === 'error' ? '#ef4444' : '#71717a'
              }}
            />
            <span className="text-[13px] text-zinc-400 capitalize">
              {cloudStatus?.status ?? t('statusLoading')}
            </span>
            {(cloudStatus?.status === 'disconnected' || cloudStatus?.status === 'error') && (
              <button
                onClick={onReconnect}
                disabled={cloudReconnecting}
                className="ml-1 flex items-center gap-1 rounded-lg px-2.5 py-1 text-[11px] font-medium text-zinc-300 transition-colors hover:text-white"
                style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-strong)' }}
              >
                <RefreshCw className={cn('h-3 w-3', cloudReconnecting && 'animate-spin')} strokeWidth={2} />
                {cloudReconnecting ? t('connecting') : t('reconnect')}
              </button>
            )}
          </div>
        </Row>
        {cloudStatus?.error && (
          <div className="flex items-start gap-2 py-2 px-0.5 -mt-2 mb-1">
            <span
              className="text-[12px] leading-snug"
              style={{ color: cloudStatus.status === 'error' ? '#ef4444' : '#f59e0b' }}
            >
              {cloudStatus.error}
            </span>
          </div>
        )}
        <Row label={t('deviceIdLabel')} desc={cloudStatus?.maskedApiKey ? t('deviceIdKeyDesc', { maskedApiKey: cloudStatus.maskedApiKey }) : undefined}>
          <span className="font-mono text-[12px] text-zinc-500">
            {cloudStatus?.deviceId?.slice(0, 8) ?? '—'}
          </span>
        </Row>
        {cloudStatus?.lastTelemetryAt && (
          <Row label={t('lastTelemetryLabel')} desc={t('lastTelemetryDesc')}>
            <span className="text-[12px] text-zinc-500">
              {new Date(cloudStatus.lastTelemetryAt).toLocaleTimeString()}
            </span>
          </Row>
        )}
        {cloudStatus?.lastHealthReportAt && (
          <Row label={t('lastHealthReportLabel')} desc={features.registry ? t('lastHealthReportDescWindows') : t('lastHealthReportDescOther')} last>
            <span className="text-[12px] text-zinc-500">
              {new Date(cloudStatus.lastHealthReportAt).toLocaleTimeString()}
            </span>
          </Row>
        )}
      </Section>

      <Section title={t('sectionMonitoring')}>
        <Row label={t('shareDiskHealthLabel')} desc={t('shareDiskHealthDesc')}>
          <Toggle checked={settings.cloud.shareDiskHealth} onChange={(v) => onSave({ cloud: { ...settings.cloud, shareDiskHealth: v } })} />
        </Row>
        <Row label={t('shareProcessListLabel')} desc={t('shareProcessListDesc')}>
          <Toggle checked={settings.cloud.shareProcessList} onChange={(v) => onSave({ cloud: { ...settings.cloud, shareProcessList: v } })} />
        </Row>
        <Row label={t('threatMonitorLabel')} desc={t('threatMonitorDesc')}>
          <Toggle checked={settings.cloud.shareThreatMonitor} onChange={(v) => onSave({ cloud: { ...settings.cloud, shareThreatMonitor: v } })} />
        </Row>
        <Row label={t('threatListLabel')} desc={cloudStatus?.threatBlacklist ? t('threatListDescLoaded', { version: cloudStatus.threatBlacklist.version, updatedDate: new Date(cloudStatus.threatBlacklist.updatedAt).toLocaleDateString() }) : t('threatListDescWaiting')}>
          {cloudStatus?.threatBlacklist ? (
            <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-ghost-2)' }}>
              {t('threatListRules', { totalRules: (cloudStatus.threatBlacklist.domains + cloudStatus.threatBlacklist.ips + cloudStatus.threatBlacklist.cidrs).toLocaleString() })}
              <span style={{ color: 'var(--text-ghost)' }}> {t('threatListBreakdown', { domains: cloudStatus.threatBlacklist.domains.toLocaleString(), ips: cloudStatus.threatBlacklist.ips.toLocaleString(), cidrs: cloudStatus.threatBlacklist.cidrs.toLocaleString() })}</span>
            </span>
          ) : (
            <span className="text-[11px]" style={{ color: 'var(--text-ghost)' }}>{t('threatListNotLoaded')}</span>
          )}
        </Row>
        <Row label={t('cveMonitorLabel')} desc={cveSummary && cveSummary.total > 0 ? t('cveDescLoaded', { findings: cveSummary.total, critical: cveSummary.critical, high: cveSummary.high, medium: cveSummary.medium, low: cveSummary.low }) : t('cveMonitorDesc')} last>
          {cveSummary && cveSummary.librarySize > 0 ? (
            <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-ghost-2)' }}>
              {t('cveLibrarySize', { count: cveSummary.librarySize.toLocaleString() })}
            </span>
          ) : (
            <span className="text-[11px]" style={{ color: 'var(--text-ghost)' }}>{cveSummary ? t('cveNoFindings') : t('cveNotScanned')}</span>
          )}
        </Row>
      </Section>

      <Section title={t('sectionRemoteControl')}>
        <Row label={t('remotePowerLabel')} desc={t('remotePowerDesc')}>
          <Toggle checked={settings.cloud.allowRemotePower} onChange={(v) => onSave({ cloud: { ...settings.cloud, allowRemotePower: v } })} />
        </Row>
        <Row label={t('remoteCleanupLabel')} desc={features.registry ? t('remoteCleanupDescWindows') : t('remoteCleanupDescOther')}>
          <Toggle checked={settings.cloud.allowRemoteCleanup} onChange={(v) => onSave({ cloud: { ...settings.cloud, allowRemoteCleanup: v } })} />
        </Row>
        <Row label={t('remoteInstallsLabel')} desc={platform === 'win32' ? t('remoteInstallsDescWindows') : t('remoteInstallsDescOther')}>
          <Toggle checked={settings.cloud.allowRemoteInstalls} onChange={(v) => onSave({ cloud: { ...settings.cloud, allowRemoteInstalls: v } })} />
        </Row>
        <Row label={t('remoteConfigLabel')} desc={t('remoteConfigDesc')} last>
          <Toggle checked={settings.cloud.allowRemoteConfig} onChange={(v) => onSave({ cloud: { ...settings.cloud, allowRemoteConfig: v } })} />
        </Row>
      </Section>

      <Section title={t('sectionAdvanced')}>
        <Row label={t('telemetryIntervalLabel')} desc={t('telemetryIntervalDesc')} last>
          <select
            value={settings.cloud.telemetryIntervalSec}
            onChange={(e) => onSave({ cloud: { ...settings.cloud, telemetryIntervalSec: Number(e.target.value) } })}
            className={selectStyle} style={selectBorder}
          >
            <option value={30}>{t('telemetryInterval30s')}</option>
            <option value={60}>{t('telemetryInterval1m')}</option>
            <option value={300}>{t('telemetryInterval5m')}</option>
            <option value={900}>{t('telemetryInterval15m')}</option>
          </select>
        </Row>
      </Section>

      <div className="mb-7">
        <button
          onClick={onUnlink}
          disabled={cloudUnlinking}
          className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[12px] font-medium text-red-400 transition-colors"
          style={{ border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <Unlink className="h-3.5 w-3.5" strokeWidth={1.8} />
          {cloudUnlinking ? t('unlinking') : t('unlinkDevice')}
        </button>
      </div>
    </>
  )
}

/* ── Shared UI helpers ──────────────────────────────────────── */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-7">
      <h3 className="mb-3 text-[11px] font-medium uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>{title}</h3>
      <div className="rounded-2xl p-5" style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}>{children}</div>
    </div>
  )
}

function Row({ label, desc, children, last }: { label: string; desc?: string; children: React.ReactNode; last?: boolean }) {
  return (
    <div className={cn('flex items-center justify-between py-3.5', !last && 'border-b')}
      style={!last ? { borderColor: 'var(--border-subtle)' } : undefined}>
      <div>
        <p className="text-[13px] font-medium text-zinc-300">{label}</p>
        {desc && <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>{desc}</p>}
      </div>
      {children}
    </div>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!checked)}
      className="relative h-[26px] w-[46px] shrink-0 rounded-full transition-colors"
      style={{ background: checked ? 'var(--accent)' : 'var(--bg-active)' }}>
      <div className={cn(
        'absolute top-[3px] h-5 w-5 rounded-full bg-white shadow-sm transition-transform',
        checked ? 'translate-x-[22px]' : 'translate-x-[3px]'
      )} />
    </button>
  )
}
