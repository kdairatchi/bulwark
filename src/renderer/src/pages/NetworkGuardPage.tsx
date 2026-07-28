import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ShieldCheck, ShieldAlert, ShieldX, Search, Globe, Activity, Radar, Network,
  RefreshCw, Lock, ChevronDown, ChevronRight, ShieldOff, Plus, Trash2, Power,
} from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { useNetworkGuardStore } from '@/stores/network-guard-store'
import type { NetworkDecision, NetworkEvent } from '@shared/network-guard'
import type { AppConnections } from '@shared/network-monitor'
import type { NetworkRule } from '@shared/policy'

const DECISION_STYLE: Record<NetworkDecision, { label: string; color: string; bg: string; border: string; Icon: typeof ShieldCheck }> = {
  allow: { label: 'Allow', color: '#4ade80', bg: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.30)', Icon: ShieldCheck },
  alert: { label: 'Alert', color: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.30)', Icon: ShieldAlert },
  block: { label: 'Block', color: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.30)', Icon: ShieldX },
}

type Tab = 'connections' | 'dns' | 'rules' | 'scan' | 'check' | 'spn'

export function NetworkGuardPage() {
  const { t } = useTranslation('networkGuard')
  const [tab, setTab] = useState<Tab>('connections')

  const tabs: { id: Tab; label: string; Icon: typeof Activity }[] = [
    { id: 'connections', label: t('tabConnections'), Icon: Activity },
    { id: 'dns', label: t('tabDns'), Icon: Lock },
    { id: 'rules', label: t('tabRules'), Icon: ShieldOff },
    { id: 'scan', label: t('tabScan'), Icon: Radar },
    { id: 'check', label: t('tabCheck'), Icon: Search },
    { id: 'spn', label: t('tabSpn'), Icon: Globe },
  ]

  return (
    <div className="p-8 animate-fade-in">
      <PageHeader title={t('pageTitle')} description={t('pageDescription')} />

      <div className="mb-6 flex gap-1.5 border-b" style={{ borderColor: 'var(--border-default)' }}>
        {tabs.map((tb) => (
          <button
            key={tb.id}
            onClick={() => setTab(tb.id)}
            className="flex items-center gap-2 border-b-2 px-4 py-2.5 text-[13px] font-medium transition-colors"
            style={{
              borderColor: tab === tb.id ? '#f59e0b' : 'transparent',
              color: tab === tb.id ? '#fafafa' : 'var(--text-muted)',
            }}>
            <tb.Icon className="h-4 w-4" strokeWidth={1.8} /> {tb.label}
          </button>
        ))}
      </div>

      {tab === 'connections' && <ConnectionsTab />}
      {tab === 'dns' && <SecureDnsTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'scan' && <PortScanTab />}
      {tab === 'check' && <CheckTab />}
      {tab === 'spn' && <SpnTab />}
    </div>
  )
}

// ─── Connections (Portmaster-style per-app monitor) ─────────

function ConnectionsTab() {
  const { t } = useTranslation('networkGuard')
  const overview = useNetworkGuardStore((s) => s.overview)
  const loading = useNetworkGuardStore((s) => s.monitorLoading)
  const refresh = useNetworkGuardStore((s) => s.refreshConnections)
  const rules = useNetworkGuardStore((s) => s.rules)
  const saveRules = useNetworkGuardStore((s) => s.saveRules)
  const loadRules = useNetworkGuardStore((s) => s.loadRules)
  const [live, setLive] = useState(true)

  useEffect(() => { if (!overview) refresh(); loadRules() }, [overview, refresh, loadRules])

  // Real-time: poll while "Live" is on and the tab is mounted.
  useEffect(() => {
    if (!live) return
    const id = setInterval(() => refresh(), 4000)
    return () => clearInterval(id)
  }, [live, refresh])

  const blockRemote = async (remote: string) => {
    const isIp = /^[0-9.]+$/.test(remote) || remote.includes(':')
    const rule: NetworkRule = {
      id: `rule_${Date.now()}`,
      name: `block ${remote}`,
      scope: { kind: 'global' },
      match: isIp ? { ip: remote } : { domain: remote },
      action: 'block',
      enabled: true,
    }
    await saveRules([...rules, rule])
    refresh()
  }
  const blockedSet = new Set(rules.filter((r) => r.action === 'block' && r.enabled).map((r) => r.match.domain || r.match.ip))

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div className="flex gap-3">
          <Stat label={t('statApps')} value={overview?.apps.length ?? 0} />
          <Stat label={t('statConnections')} value={overview?.totalConnections ?? 0} />
          <Stat label={t('statBlocked')} value={overview?.blocked ?? 0} color="#f87171" />
          <Stat label={t('statAlerted')} value={overview?.alerted ?? 0} color="#fbbf24" />
          <Stat label={t('statListening')} value={overview?.listeningPorts.length ?? 0} />
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setLive((v) => !v)}
            className="flex items-center gap-2 rounded-xl px-3 py-2 text-[12px] font-medium transition-colors"
            style={{ background: live ? 'rgba(34,197,94,0.12)' : 'var(--bg-hover-2)', color: live ? '#4ade80' : 'var(--text-muted)', border: `1px solid ${live ? 'rgba(34,197,94,0.3)' : 'var(--border-default)'}` }}>
            <span className="relative flex h-2 w-2">
              {live && <span className="absolute inline-flex h-full w-full animate-ping rounded-full" style={{ background: '#4ade80', opacity: 0.75 }} />}
              <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: live ? '#4ade80' : 'var(--text-muted)' }} />
            </span>
            {live ? t('live') : t('paused')}
          </button>
          <button
            onClick={() => refresh()}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl px-4 py-2 text-[12px] font-medium text-zinc-200 transition-colors disabled:opacity-60"
            style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} strokeWidth={1.8} /> {t('refresh')}
          </button>
        </div>
      </div>

      {loading && !overview && <Centered text={t('loadingConnections')} />}
      {overview && overview.apps.length === 0 && (
        <div className="rounded-xl px-4 py-10 text-center text-[13px]" style={{ color: 'var(--text-muted)', border: '1px solid var(--border-default)' }}>
          {t('noConnections')}
        </div>
      )}
      <div className="space-y-2.5">
        {overview?.apps.map((app, i) => <AppRow key={`${app.app}-${app.pid}-${i}`} app={app} onBlock={blockRemote} blockedSet={blockedSet} />)}
      </div>

      {overview && overview.listeningPorts.length > 0 && (
        <div className="mt-6">
          <p className="mb-2 text-[12px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{t('listeningTitle')}</p>
          <div className="flex flex-wrap gap-1.5">
            {overview.listeningPorts.map((p) => (
              <span key={p} className="rounded-md px-2 py-1 font-mono text-[11px]" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)', color: 'var(--text-muted)' }}>{p}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function AppRow({ app, onBlock, blockedSet }: { app: AppConnections; onBlock: (remote: string) => void; blockedSet: Set<string | undefined> }) {
  const { t } = useTranslation('networkGuard')
  const [open, setOpen] = useState(false)
  const s = DECISION_STYLE[app.worst]
  const Caret = open ? ChevronDown : ChevronRight
  return (
    <div className="rounded-xl" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <Caret className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
        <Network className="h-4 w-4 shrink-0" style={{ color: s.color }} strokeWidth={1.8} />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-zinc-100">{app.app}</span>
        {app.pid != null && <span className="shrink-0 font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>pid {app.pid}</span>}
        <span className="shrink-0 text-[12px]" style={{ color: 'var(--text-muted)' }}>{app.count} conn</span>
        {app.worst !== 'allow' && (
          <span className="shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-semibold" style={{ color: s.color, background: `${s.color}1a`, border: `1px solid ${s.color}40` }}>{s.label}</span>
        )}
      </button>
      {open && (
        <div className="border-t px-4 py-2" style={{ borderColor: s.border }}>
          {app.connections.map((c, i) => {
            const cs = DECISION_STYLE[c.decision]
            const isBlocked = blockedSet.has(c.remoteAddress)
            return (
              <div key={i} className="group flex items-center gap-3 py-1.5 font-mono text-[12px]">
                <span className="min-w-0 flex-1 truncate text-zinc-300">{c.remoteAddress}:{c.remotePort}</span>
                {c.country && <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: 'var(--bg-hover)', color: 'var(--text-muted)' }}>{c.country}</span>}
                {c.category && <span style={{ color: 'var(--text-muted)' }}>{c.reason}</span>}
                <span style={{ color: cs.color }}>{cs.label}</span>
                {isBlocked ? (
                  <span className="shrink-0 text-[11px]" style={{ color: '#f87171' }}>{t('ruleBlocked')}</span>
                ) : (
                  <button
                    onClick={(e) => { e.stopPropagation(); onBlock(c.remoteAddress) }}
                    className="shrink-0 rounded-md px-2 py-0.5 text-[11px] font-medium opacity-0 transition-opacity group-hover:opacity-100"
                    style={{ color: '#f87171', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}>
                    {t('blockBtn')}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Port scanner ───────────────────────────────────────────

function PortScanTab() {
  const { t } = useTranslation('networkGuard')
  const scan = useNetworkGuardStore((s) => s.scanPorts)
  const scanning = useNetworkGuardStore((s) => s.scanning)
  const result = useNetworkGuardStore((s) => s.scanResult)
  const [host, setHost] = useState('127.0.0.1')
  const [ports, setPorts] = useState('top')

  return (
    <div className="glass-card rounded-2xl p-6">
      <div className="grid grid-cols-[1fr_1fr_auto] gap-2.5">
        <Labeled label={t('host')}>
          <input value={host} onChange={(e) => setHost(e.target.value)} className="w-full rounded-xl px-3.5 py-2.5 text-[13px] text-zinc-100 outline-none" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }} placeholder="127.0.0.1" />
        </Labeled>
        <Labeled label={t('ports')}>
          <input value={ports} onChange={(e) => setPorts(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') scan(host, ports) }} className="w-full rounded-xl px-3.5 py-2.5 text-[13px] text-zinc-100 outline-none" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }} placeholder="top, 1-1024, 22,80,443" />
        </Labeled>
        <div className="flex items-end">
          <button
            onClick={() => scan(host, ports)}
            disabled={scanning}
            className="flex h-[42px] items-center gap-2 rounded-xl px-5 text-[12px] font-medium text-zinc-100 transition-colors disabled:opacity-60"
            style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
            <Radar className={`h-3.5 w-3.5 ${scanning ? 'animate-spin' : ''}`} strokeWidth={1.8} /> {scanning ? t('scanningPorts') : t('scan')}
          </button>
        </div>
      </div>
      <p className="mt-2 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('scanHint')}</p>

      {result && (
        <div className="mt-5">
          {result.error ? (
            <p className="text-[13px]" style={{ color: '#f87171' }}>{result.error}</p>
          ) : (
            <>
              <p className="mb-3 text-[12px]" style={{ color: 'var(--text-muted)' }}>
                {t('scanSummary', { open: result.openPorts.length, scanned: result.scanned, host: result.host, ms: result.durationMs })}
              </p>
              <div className="space-y-2">
                {result.openPorts.length === 0 && (
                  <p className="text-[13px]" style={{ color: 'var(--text-muted)' }}>{t('noOpenPorts')}</p>
                )}
                {result.openPorts.map((p) => (
                  <div key={p.port} className="flex items-center gap-3 rounded-lg px-4 py-2.5 text-[13px]" style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)' }}>
                    <span className="font-mono font-semibold text-zinc-100">{p.port}</span>
                    <span className="rounded-md px-2 py-0.5 text-[11px]" style={{ background: 'rgba(34,197,94,0.15)', color: '#4ade80' }}>{t('open')}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{p.service}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Destination checker ────────────────────────────────────

function CheckTab() {
  const { t } = useTranslation('networkGuard')
  const feedText = useNetworkGuardStore((s) => s.feedText)
  const setFeedText = useNetworkGuardStore((s) => s.setFeedText)
  const check = useNetworkGuardStore((s) => s.check)
  const checking = useNetworkGuardStore((s) => s.checking)
  const error = useNetworkGuardStore((s) => s.error)
  const result = useNetworkGuardStore((s) => s.result)
  const [target, setTarget] = useState('')

  return (
    <div className="glass-card rounded-2xl p-6">
      <label className="mb-2 block text-[12px] font-medium" style={{ color: 'var(--text-muted)' }}>{t('checkLabel')}</label>
      <div className="flex gap-2.5">
        <div className="flex flex-1 items-center gap-2 rounded-xl px-3.5" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
          <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
          <input value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') check(target) }} placeholder={t('placeholder')} className="w-full bg-transparent py-2.5 text-[13px] text-zinc-100 outline-none" />
        </div>
        <button onClick={() => check(target)} disabled={checking} className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-[12px] font-medium text-zinc-100 transition-colors disabled:opacity-60" style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
          <Search className={`h-3.5 w-3.5 ${checking ? 'animate-pulse' : ''}`} strokeWidth={1.8} /> {checking ? t('checking') : t('check')}
        </button>
      </div>
      {error && <p className="mt-3 text-[12px]" style={{ color: '#f87171' }}>{error}</p>}
      {result && <VerdictCard event={result} />}

      <details className="mt-5">
        <summary className="cursor-pointer text-[13px] font-medium text-zinc-200">{t('feedTitle')}</summary>
        <p className="mb-2 mt-2 text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('feedHint')}</p>
        <textarea value={feedText} onChange={(e) => setFeedText(e.target.value)} spellCheck={false} className="h-48 w-full rounded-xl p-3 font-mono text-[11px] text-zinc-200 outline-none" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }} />
      </details>
    </div>
  )
}

function VerdictCard({ event }: { event: NetworkEvent }) {
  const { t } = useTranslation('networkGuard')
  const s = DECISION_STYLE[event.decision]
  return (
    <div className="mt-5 rounded-xl p-4" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <div className="flex items-center gap-3">
        <s.Icon className="h-6 w-6 shrink-0" style={{ color: s.color }} strokeWidth={1.8} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-[14px] font-semibold text-zinc-100">{event.destination}</p>
          <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>{event.destinationType.toUpperCase()}{event.port ? ` · port ${event.port}` : ''}</p>
        </div>
        <span className="shrink-0 rounded-full px-3 py-1 text-[12px] font-semibold" style={{ color: s.color, background: `${s.color}1a`, border: `1px solid ${s.color}40` }}>{s.label}</span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-3 text-[12px]">
        <Field label={t('reason')} value={event.reason} />
        <Field label={t('category')} value={event.category ?? '—'} />
        <Field label={t('confidence')} value={event.decision === 'allow' ? '—' : `${Math.round(event.confidence * 100)}%`} />
      </div>
      {event.matchedIndicator && (
        <p className="mt-3 text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('matched')}: <span className="font-mono text-zinc-300">{event.matchedIndicator}</span></p>
      )}
    </div>
  )
}

// ─── Secure DNS (DNS-over-TLS filtering resolver) ───────────

function SecureDnsTab() {
  const { t } = useTranslation('networkGuard')
  const dns = useNetworkGuardStore((s) => s.dns)
  const busy = useNetworkGuardStore((s) => s.dnsBusy)
  const status = useNetworkGuardStore((s) => s.dnsStatus)
  const toggle = useNetworkGuardStore((s) => s.dnsToggle)

  const enforcement = useNetworkGuardStore((s) => s.enforcement)
  const enforceBusy = useNetworkGuardStore((s) => s.enforceBusy)
  const loadEnforcement = useNetworkGuardStore((s) => s.loadEnforcement)
  const toggleEnforcement = useNetworkGuardStore((s) => s.toggleEnforcement)

  useEffect(() => { status(); loadEnforcement() }, [status, loadEnforcement])
  const running = dns?.running
  const enforcing = enforcement?.enforcing

  return (
    <div>
      <div className="glass-card flex items-center gap-5 rounded-2xl p-6">
        <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl" style={{ background: running ? 'rgba(34,197,94,0.12)' : 'var(--bg-hover-2)', border: `1px solid ${running ? 'rgba(34,197,94,0.3)' : 'var(--border-default)'}` }}>
          <Lock className="h-8 w-8" style={{ color: running ? '#22c55e' : 'var(--text-muted)' }} strokeWidth={1.6} />
        </div>
        <div className="flex-1">
          <p className="text-[15px] font-semibold text-white">{t('dnsTitle')}</p>
          <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>
            {running ? t('dnsRunningAt', { address: dns?.address }) : t('dnsStopped')}
          </p>
          <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('dnsUpstream', { upstream: dns?.upstream ?? '—' })}</p>
        </div>
        <button
          onClick={() => toggle()}
          disabled={busy}
          className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-[12px] font-medium transition-colors disabled:opacity-60"
          style={{ background: running ? 'rgba(239,68,68,0.15)' : 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)', color: running ? '#f87171' : '#fafafa', border: running ? '1px solid rgba(239,68,68,0.3)' : 'none' }}>
          <Power className="h-3.5 w-3.5" strokeWidth={1.8} /> {running ? t('dnsStop') : t('dnsStart')}
        </button>
      </div>

      {running && (
        <>
          <div className="mt-4 flex flex-wrap gap-3">
            <Stat label={t('dnsTotal')} value={dns?.totalQueries ?? 0} />
            <Stat label={t('dnsBlocked')} value={dns?.blockedQueries ?? 0} color="#f87171" />
            <Stat label={t('dnsForwarded')} value={dns?.forwardedQueries ?? 0} color="#4ade80" />
            <Stat label={t('dnsFilterSize')} value={dns?.filterListSize ?? 0} />
            <button onClick={() => status()} className="flex items-center gap-2 self-center rounded-xl px-3 py-2 text-[12px]" style={{ color: 'var(--text-muted)', border: '1px solid var(--border-default)' }}>
              <RefreshCw className="h-3.5 w-3.5" strokeWidth={1.8} /> {t('refresh')}
            </button>
          </div>
          <div className="mt-4 rounded-xl p-4" style={{ background: enforcing ? 'rgba(34,197,94,0.08)' : 'var(--bg-hover-2)', border: `1px solid ${enforcing ? 'rgba(34,197,94,0.3)' : 'var(--border-default)'}` }}>
            <div className="flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-semibold text-zinc-100">{t('enforceTitle')}</p>
                <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>
                  {enforcing ? t('enforceOn') : t('enforceOff', { address: dns?.address })}
                </p>
                {enforcement?.message && <p className="mt-1 text-[12px]" style={{ color: '#fbbf24' }}>{enforcement.message}</p>}
              </div>
              <button
                onClick={() => toggleEnforcement()}
                disabled={enforceBusy}
                className="flex shrink-0 items-center gap-2 rounded-xl px-4 py-2 text-[12px] font-medium transition-colors disabled:opacity-60"
                style={{ background: enforcing ? 'rgba(239,68,68,0.15)' : 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)', color: enforcing ? '#f87171' : '#fafafa', border: enforcing ? '1px solid rgba(239,68,68,0.3)' : 'none' }}>
                <ShieldCheck className="h-3.5 w-3.5" strokeWidth={1.8} /> {enforcing ? t('enforceDisable') : t('enforceEnable')}
              </button>
            </div>
            {!enforcing && <p className="mt-2 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('enforceWarn')}</p>}
          </div>

          {dns && dns.recent.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[12px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{t('dnsRecent')}</p>
              <div className="space-y-1.5">
                {dns.recent.slice(0, 15).map((e, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-lg px-4 py-2 font-mono text-[12px]" style={{ background: e.blocked ? 'rgba(239,68,68,0.06)' : 'var(--bg-hover-2)', border: `1px solid ${e.blocked ? 'rgba(239,68,68,0.2)' : 'var(--border-default)'}` }}>
                    <span className="min-w-0 flex-1 truncate text-zinc-200">{e.name}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{e.type}</span>
                    <span style={{ color: e.blocked ? '#f87171' : '#4ade80' }}>{e.blocked ? t('dnsBlockedTag') : e.via}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      <FilterListsPanel />
    </div>
  )
}

function FilterListsPanel() {
  const { t } = useTranslation('networkGuard')
  const state = useNetworkGuardStore((s) => s.filterLists)
  const syncing = useNetworkGuardStore((s) => s.filterSyncing)
  const load = useNetworkGuardStore((s) => s.loadFilterLists)
  const toggle = useNetworkGuardStore((s) => s.toggleFilterList)
  const sync = useNetworkGuardStore((s) => s.syncFilterLists)

  useEffect(() => { if (!state) load() }, [state, load])

  return (
    <div className="mt-6 glass-card rounded-2xl p-6">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <p className="text-[14px] font-semibold text-white">{t('filterListsTitle')}</p>
          <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>
            {t('filterListsTotal', { total: (state?.totalDomains ?? 0).toLocaleString() })}
          </p>
        </div>
        <button
          onClick={() => sync()}
          disabled={syncing}
          className="flex items-center gap-2 rounded-xl px-4 py-2 text-[12px] font-medium text-zinc-100 transition-colors disabled:opacity-60"
          style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
          <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} strokeWidth={1.8} /> {syncing ? t('filterListsUpdating') : t('filterListsUpdate')}
        </button>
      </div>
      <div className="space-y-2">
        {state?.lists.map((l) => (
          <div key={l.id} className="flex items-center gap-3 rounded-xl px-4 py-3 text-[13px]" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
            <input type="checkbox" checked={l.enabled} onChange={(e) => toggle(l.id, e.target.checked)} className="h-4 w-4 accent-amber-500" />
            <div className="min-w-0 flex-1">
              <p className="truncate font-medium text-zinc-100">{l.name} <span className="ml-1 rounded-md px-1.5 py-0.5 text-[10px]" style={{ background: 'var(--bg-hover)', color: 'var(--text-muted)' }}>{l.category}</span></p>
              <p className="truncate text-[11px]" style={{ color: 'var(--text-muted)' }}>{l.description}</p>
              {l.lastError && <p className="text-[11px]" style={{ color: '#f87171' }}>{l.lastError}</p>}
            </div>
            <span className="shrink-0 font-mono text-[12px]" style={{ color: l.cached ? '#4ade80' : 'var(--text-muted)' }}>
              {l.cached ? t('filterListsCount', { count: l.domainCount.toLocaleString() }) : t('filterListsNotSynced')}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Rules ──────────────────────────────────────────────────

function RulesTab() {
  const { t } = useTranslation('networkGuard')
  const rules = useNetworkGuardStore((s) => s.rules)
  const load = useNetworkGuardStore((s) => s.loadRules)
  const save = useNetworkGuardStore((s) => s.saveRules)
  const geoip = useNetworkGuardStore((s) => s.geoip)
  const geoipSyncing = useNetworkGuardStore((s) => s.geoipSyncing)
  const loadGeoip = useNetworkGuardStore((s) => s.loadGeoip)
  const syncGeoip = useNetworkGuardStore((s) => s.syncGeoip)
  const [kind, setKind] = useState<'domain' | 'country'>('domain')
  const [value, setValue] = useState('')
  const [action, setAction] = useState<'block' | 'allow'>('block')

  useEffect(() => { load(); loadGeoip() }, [load, loadGeoip])

  const add = () => {
    const v = value.trim()
    if (!v) return
    const match = kind === 'country' ? { country: v.toUpperCase() } : { domain: v.toLowerCase() }
    const rule: NetworkRule = {
      id: `rule_${Date.now()}`,
      name: `${action} ${kind === 'country' ? 'country ' : ''}${v}`,
      scope: { kind: 'global' },
      match,
      action,
      enabled: true,
    }
    save([...rules, rule])
    setValue('')
  }
  const remove = (id: string) => save(rules.filter((r) => r.id !== id))
  const toggle = (id: string) => save(rules.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)))

  return (
    <div className="glass-card rounded-2xl p-6">
      <p className="mb-3 text-[13px]" style={{ color: 'var(--text-muted)' }}>{t('rulesHint')}</p>
      <div className="flex flex-wrap gap-2.5">
        <select value={kind} onChange={(e) => setKind(e.target.value as 'domain' | 'country')} className="rounded-xl px-3 text-[13px] text-zinc-100 outline-none" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
          <option value="domain">{t('rulesKindDomain')}</option>
          <option value="country">{t('rulesKindCountry')}</option>
        </select>
        <div className="flex flex-1 items-center gap-2 rounded-xl px-3.5" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
          <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
          <input value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') add() }} placeholder={kind === 'country' ? t('rulesCountryPlaceholder') : t('rulesPlaceholder')} className="w-full bg-transparent py-2.5 text-[13px] text-zinc-100 outline-none" />
        </div>
        <select value={action} onChange={(e) => setAction(e.target.value as 'block' | 'allow')} className="rounded-xl px-3 text-[13px] text-zinc-100 outline-none" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
          <option value="block">{t('rulesBlock')}</option>
          <option value="allow">{t('rulesAllow')}</option>
        </select>
        <button onClick={add} className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-[12px] font-medium text-zinc-100" style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
          <Plus className="h-3.5 w-3.5" strokeWidth={1.8} /> {t('rulesAdd')}
        </button>
      </div>

      {kind === 'country' && (
        <div className="mt-3 flex items-center gap-3 rounded-xl px-4 py-2.5 text-[12px]" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
          <Globe className="h-4 w-4 shrink-0" style={{ color: geoip?.ready ? '#4ade80' : 'var(--text-muted)' }} />
          <span className="flex-1" style={{ color: 'var(--text-muted)' }}>
            {geoip?.ready ? t('geoipReady', { count: geoip.ranges.toLocaleString() }) : t('geoipNotReady')}
          </span>
          <button onClick={() => syncGeoip()} disabled={geoipSyncing} className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11px] font-medium text-zinc-100 disabled:opacity-60" style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
            <RefreshCw className={`h-3 w-3 ${geoipSyncing ? 'animate-spin' : ''}`} strokeWidth={1.8} /> {geoipSyncing ? t('geoipUpdating') : t('geoipUpdate')}
          </button>
        </div>
      )}

      <div className="mt-5 space-y-2">
        {rules.length === 0 && <p className="text-[13px]" style={{ color: 'var(--text-muted)' }}>{t('rulesEmpty')}</p>}
        {rules.map((r) => {
          const isBlock = r.action === 'block'
          const color = isBlock ? '#f87171' : '#4ade80'
          const label = r.match.country ? `country: ${r.match.country}` : (r.match.domain || r.match.ip || r.match.category || '*')
          return (
            <div key={r.id} className="flex items-center gap-3 rounded-xl px-4 py-2.5 text-[13px]" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)', opacity: r.enabled ? 1 : 0.5 }}>
              <span className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold" style={{ color, background: `${color}1a`, border: `1px solid ${color}40` }}>{isBlock ? t('rulesBlock') : t('rulesAllow')}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-zinc-200">{label}</span>
              <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{r.scope.kind === 'app' ? r.scope.app : t('rulesGlobal')}</span>
              <button onClick={() => toggle(r.id)} className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{r.enabled ? t('rulesOn') : t('rulesOff')}</button>
              <button onClick={() => remove(r.id)} style={{ color: '#f87171' }}><Trash2 className="h-4 w-4" strokeWidth={1.8} /></button>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── SPN (planned) ──────────────────────────────────────────

function SpnTab() {
  const { t } = useTranslation('networkGuard')
  return (
    <div className="glass-card rounded-2xl p-8 text-center">
      <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl" style={{ background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.3)' }}>
        <Lock className="h-8 w-8" style={{ color: '#f59e0b' }} strokeWidth={1.6} />
      </div>
      <p className="text-[16px] font-semibold text-white">{t('spnTitle')}</p>
      <span className="mt-2 inline-block rounded-full px-3 py-1 text-[11px] font-semibold" style={{ background: 'rgba(245,158,11,0.12)', color: '#fbbf24', border: '1px solid rgba(245,158,11,0.3)' }}>{t('spnPlanned')}</span>
      <p className="mx-auto mt-4 max-w-xl text-[13px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>{t('spnDescription')}</p>
    </div>
  )
}

// ─── Shared bits ────────────────────────────────────────────

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="rounded-xl px-3.5 py-2" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
      <p className="text-[18px] font-bold leading-none" style={{ color: color ?? '#fafafa' }}>{value}</p>
      <p className="mt-1 text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</p>
    </div>
  )
}

function Labeled({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="mb-1.5 block text-[11px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</label>
      {children}
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{label}</p>
      <p className="mt-0.5 font-medium text-zinc-200">{value}</p>
    </div>
  )
}

function Centered({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="h-5 w-5 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
      <span className="ml-3 text-[13px]" style={{ color: 'var(--text-muted)' }}>{text}</span>
    </div>
  )
}
