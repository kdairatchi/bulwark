import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, ShieldAlert, ShieldX, Search, Globe } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { useNetworkGuardStore } from '@/stores/network-guard-store'
import type { NetworkDecision, NetworkEvent } from '@shared/network-guard'

const DECISION_STYLE: Record<NetworkDecision, { label: string; color: string; bg: string; border: string; Icon: typeof ShieldCheck }> = {
  allow: { label: 'Allow', color: '#4ade80', bg: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.30)', Icon: ShieldCheck },
  alert: { label: 'Alert', color: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.30)', Icon: ShieldAlert },
  block: { label: 'Block', color: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.30)', Icon: ShieldX },
}

export function NetworkGuardPage() {
  const { t } = useTranslation('networkGuard')
  const feedText = useNetworkGuardStore((s) => s.feedText)
  const setFeedText = useNetworkGuardStore((s) => s.setFeedText)
  const check = useNetworkGuardStore((s) => s.check)
  const checking = useNetworkGuardStore((s) => s.checking)
  const error = useNetworkGuardStore((s) => s.error)
  const result = useNetworkGuardStore((s) => s.result)
  const history = useNetworkGuardStore((s) => s.history)
  const [target, setTarget] = useState('')

  const onCheck = () => check(target)

  return (
    <div className="p-8 animate-fade-in">
      <PageHeader title={t('pageTitle')} description={t('pageDescription')} />

      <div className="glass-card rounded-2xl p-6">
        <label className="mb-2 block text-[12px] font-medium" style={{ color: 'var(--text-muted)' }}>{t('checkLabel')}</label>
        <div className="flex gap-2.5">
          <div className="flex flex-1 items-center gap-2 rounded-xl px-3.5" style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}>
            <Globe className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') onCheck() }}
              placeholder={t('placeholder')}
              className="w-full bg-transparent py-2.5 text-[13px] text-zinc-100 outline-none"
            />
          </div>
          <button
            onClick={onCheck}
            disabled={checking}
            className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-[12px] font-medium text-zinc-100 transition-colors disabled:opacity-60"
            style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
            <Search className={`h-3.5 w-3.5 ${checking ? 'animate-pulse' : ''}`} strokeWidth={1.8} />
            {checking ? t('checking') : t('check')}
          </button>
        </div>
        {error && <p className="mt-3 text-[12px]" style={{ color: '#f87171' }}>{error}</p>}
        {result && <VerdictCard event={result} />}
      </div>

      {history.length > 1 && (
        <div className="mt-6">
          <p className="mb-2.5 text-[12px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{t('recent')}</p>
          <div className="space-y-2">
            {history.slice(1).map((h, i) => <HistoryRow key={i} event={h.event} />)}
          </div>
        </div>
      )}

      <details className="mt-6 rounded-2xl p-5 glass-card">
        <summary className="cursor-pointer text-[13px] font-medium text-zinc-200">{t('feedTitle')}</summary>
        <p className="mb-2 mt-2 text-[12px]" style={{ color: 'var(--text-muted)' }}>{t('feedHint')}</p>
        <textarea
          value={feedText}
          onChange={(e) => setFeedText(e.target.value)}
          spellCheck={false}
          className="h-56 w-full rounded-xl p-3 font-mono text-[11px] text-zinc-200 outline-none"
          style={{ background: 'var(--bg-hover-2)', border: '1px solid var(--border-default)' }}
        />
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
          <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
            {event.destinationType.toUpperCase()}{event.port ? ` · port ${event.port}` : ''}
          </p>
        </div>
        <span className="shrink-0 rounded-full px-3 py-1 text-[12px] font-semibold" style={{ color: s.color, background: `${s.color}1a`, border: `1px solid ${s.color}40` }}>
          {s.label}
        </span>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-3 text-[12px]">
        <Field label={t('reason')} value={event.reason} />
        <Field label={t('category')} value={event.category ?? '—'} />
        <Field label={t('confidence')} value={event.decision === 'allow' ? '—' : `${Math.round(event.confidence * 100)}%`} />
      </div>
      {event.matchedIndicator && (
        <p className="mt-3 text-[12px]" style={{ color: 'var(--text-muted)' }}>
          {t('matched')}: <span className="font-mono text-zinc-300">{event.matchedIndicator}</span>
        </p>
      )}
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

function HistoryRow({ event }: { event: NetworkEvent }) {
  const s = DECISION_STYLE[event.decision]
  return (
    <div className="flex items-center gap-3 rounded-lg px-4 py-2.5 text-[12px]" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <s.Icon className="h-4 w-4 shrink-0" style={{ color: s.color }} strokeWidth={1.8} />
      <span className="min-w-0 flex-1 truncate font-medium text-zinc-200">{event.destination}</span>
      <span style={{ color: 'var(--text-muted)' }}>{event.reason}</span>
      <span className="rounded-full px-2 py-0.5 text-[11px] font-semibold" style={{ color: s.color }}>{s.label}</span>
    </div>
  )
}
