import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, ShieldAlert, ShieldQuestion, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { useAppRiskStore } from '@/stores/app-risk-store'
import type { Finding, RiskLevel } from '@shared/risk'

const LEVEL_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low', 'safe']

const LEVEL_STYLE: Record<RiskLevel, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'Critical', color: '#f87171', bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.30)' },
  high: { label: 'High', color: '#fb923c', bg: 'rgba(249,115,22,0.10)', border: 'rgba(249,115,22,0.30)' },
  medium: { label: 'Medium', color: '#fbbf24', bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.30)' },
  low: { label: 'Low', color: '#a3a3a3', bg: 'rgba(163,163,163,0.08)', border: 'rgba(163,163,163,0.20)' },
  safe: { label: 'Safe', color: '#4ade80', bg: 'rgba(34,197,94,0.10)', border: 'rgba(34,197,94,0.25)' },
}

const MAX_ROWS = 60

export function ApplicationRiskPage() {
  const { t } = useTranslation('appRisk')
  const report = useAppRiskStore((s) => s.report)
  const status = useAppRiskStore((s) => s.status)
  const error = useAppRiskStore((s) => s.error)
  const scan = useAppRiskStore((s) => s.scan)
  const [filter, setFilter] = useState<RiskLevel | 'all'>('all')

  useEffect(() => {
    if (status === 'idle') scan()
  }, [status, scan])

  // Default the filter to the worst non-empty level so attention lands there.
  useEffect(() => {
    if (!report) return
    const worst = LEVEL_ORDER.find((lvl) => (report.summary[lvl] ?? 0) > 0 && lvl !== 'safe')
    if (worst) setFilter(worst)
  }, [report])

  const filtered = useMemo(() => {
    if (!report) return []
    return filter === 'all' ? report.findings : report.findings.filter((f) => f.level === filter)
  }, [report, filter])

  const scanning = status === 'loading'

  const rescanButton = (
    <button
      onClick={() => scan()}
      disabled={scanning}
      className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-[12px] font-medium text-zinc-200 transition-colors disabled:opacity-60"
      style={{ background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)' }}>
      <RefreshCw className={`h-3.5 w-3.5 ${scanning ? 'animate-spin' : ''}`} strokeWidth={1.8} />
      {scanning ? t('scanning') : t('rescan')}
    </button>
  )

  return (
    <div className="p-8 animate-fade-in">
      <PageHeader title={t('pageTitle')} description={t('pageDescription')} action={rescanButton} />

      {error && (
        <div className="mb-6 rounded-xl px-4 py-3 text-[13px]" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171' }}>
          {error}
        </div>
      )}

      {!report && scanning && (
        <div className="flex items-center justify-center py-24">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
          <span className="ml-3 text-[13px]" style={{ color: 'var(--text-muted)' }}>{t('scanning')}</span>
        </div>
      )}

      {report && (
        <>
          <PostureCard
            postureScore={report.postureScore}
            total={report.total}
            needsAttention={(report.familySummary.needs_attention ?? 0) + (report.familySummary.dangerous ?? 0)}
          />

          <div className="mt-6 flex flex-wrap gap-2">
            <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label={t('all')} count={report.total} color="#e4e4e7" />
            {LEVEL_ORDER.map((lvl) => (
              <FilterChip
                key={lvl}
                active={filter === lvl}
                onClick={() => setFilter(lvl)}
                label={LEVEL_STYLE[lvl].label}
                count={report.summary[lvl] ?? 0}
                color={LEVEL_STYLE[lvl].color}
              />
            ))}
          </div>

          <div className="mt-5 space-y-2.5">
            {filtered.length === 0 && (
              <div className="rounded-xl px-4 py-10 text-center text-[13px]" style={{ color: 'var(--text-muted)', border: '1px solid var(--border-default)' }}>
                {t('emptyForFilter')}
              </div>
            )}
            {filtered.slice(0, MAX_ROWS).map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
            {filtered.length > MAX_ROWS && (
              <div className="px-1 pt-1 text-[12px]" style={{ color: 'var(--text-muted)' }}>
                {t('andMore', { count: filtered.length - MAX_ROWS })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}

function PostureCard({ postureScore, total, needsAttention }: { postureScore: number; total: number; needsAttention: number }) {
  const { t } = useTranslation('appRisk')
  const protectedState = needsAttention === 0
  const Icon = protectedState ? ShieldCheck : ShieldAlert
  const accent = protectedState ? '#22c55e' : '#f59e0b'
  return (
    <div className="glass-card flex items-center gap-6 rounded-2xl p-6">
      <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl" style={{ background: `${accent}1a`, border: `1px solid ${accent}40` }}>
        <Icon className="h-9 w-9" style={{ color: accent }} strokeWidth={1.6} />
      </div>
      <div className="flex-1">
        <div className="flex items-baseline gap-2">
          <span className="text-[34px] font-bold leading-none text-white">{postureScore}</span>
          <span className="text-[14px]" style={{ color: 'var(--text-muted)' }}>/ 100</span>
        </div>
        <p className="mt-1 text-[15px] font-semibold" style={{ color: accent }}>
          {protectedState ? t('protected') : t('needsAttention')}
        </p>
        <p className="mt-0.5 text-[12px]" style={{ color: 'var(--text-muted)' }}>
          {t('assessedSummary', { total, needsAttention })}
        </p>
      </div>
    </div>
  )
}

function FilterChip({ active, onClick, label, count, color }: { active: boolean; onClick: () => void; label: string; count: number; color: string }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 rounded-full px-3.5 py-1.5 text-[12px] font-medium transition-colors"
      style={{
        background: active ? `${color}1f` : 'transparent',
        border: `1px solid ${active ? color + '66' : 'var(--border-default)'}`,
        color: active ? '#fafafa' : 'var(--text-muted)',
      }}>
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
      <span style={{ color: 'var(--text-muted)' }}>{count}</span>
    </button>
  )
}

function FindingRow({ finding }: { finding: Finding }) {
  const { t } = useTranslation('appRisk')
  const [open, setOpen] = useState(false)
  const s = LEVEL_STYLE[finding.level]
  const Caret = open ? ChevronDown : ChevronRight
  const StatusIcon = finding.familyStatus === 'unknown' ? ShieldQuestion : finding.familyStatus === 'safe' ? ShieldCheck : ShieldAlert
  return (
    <div className="rounded-xl" style={{ background: s.bg, border: `1px solid ${s.border}` }}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <Caret className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
        <StatusIcon className="h-4 w-4 shrink-0" style={{ color: s.color }} strokeWidth={1.8} />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-zinc-100">{finding.subjectName}</span>
        <span className="shrink-0 text-[11px]" style={{ color: 'var(--text-muted)' }}>{t('confidenceLabel', { level: finding.confidence })}</span>
        <span className="shrink-0 rounded-full px-2.5 py-0.5 text-[11px] font-semibold" style={{ color: s.color, background: `${s.color}1a`, border: `1px solid ${s.color}40` }}>
          {s.label}
        </span>
      </button>
      {open && (
        <div className="border-t px-4 py-3 text-[12px]" style={{ borderColor: s.border }}>
          <p className="mb-1.5 font-semibold text-zinc-300">{t('why')}</p>
          <ul className="space-y-1">
            {finding.evidence.map((line, i) => (
              <li key={i} className="flex gap-2" style={{ color: 'var(--text-muted)' }}>
                <span style={{ color: s.color }}>•</span>
                <span>{line}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 rounded-lg px-3 py-2" style={{ background: 'var(--bg-hover-2)', color: '#e4e4e7' }}>
            <span className="font-semibold">{t('recommended')}:</span> {finding.recommendedAction}
          </p>
        </div>
      )}
    </div>
  )
}
