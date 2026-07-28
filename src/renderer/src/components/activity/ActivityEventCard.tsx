import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, HelpCircle } from 'lucide-react'
import type { ActivityLogMode, BulwarkEvent } from '@shared/activity-event'
import {
  confidenceDisplay,
  explainEvent,
  formatEventCardTime,
  formatEventHeadline,
  severityDisplay,
} from '@shared/activity-explain'

const MODE_LABELS: Record<ActivityLogMode, string> = {
  simple: 'Simple',
  advanced: 'Advanced',
  raw: 'Raw',
}

function severityColor(severity: BulwarkEvent['severity']): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return '#f87171'
    case 'medium':
      return '#fbbf24'
    case 'low':
      return '#93c5fd'
    default:
      return 'var(--text-muted)'
  }
}

export function ActivityEventCard({
  event,
  defaultMode = 'simple',
  compact = false,
}: {
  event: BulwarkEvent
  defaultMode?: ActivityLogMode
  compact?: boolean
}) {
  const [mode, setMode] = useState<ActivityLogMode>(defaultMode)
  const [explainOpen, setExplainOpen] = useState(false)
  const levels = useMemo(() => explainEvent(event), [event])

  return (
    <div
      className="rounded-xl px-3 py-2.5 text-[12px]"
      style={{
        background: 'var(--bg-subtle)',
        border: '1px solid var(--border-medium)',
        color: 'var(--text-secondary)',
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="font-medium text-[13px]" style={{ color: 'var(--text-primary)' }}>
            {formatEventHeadline(event)}
          </div>
          {!compact && (
            <div className="mt-0.5 text-[11px]" style={{ color: 'var(--text-dim)' }}>
              {formatEventCardTime(event.timestamp)}
              {event.source.deviceName ? ` · ${event.source.deviceName}` : ''}
              {' · '}
              <span style={{ color: severityColor(event.severity) }}>
                {severityDisplay(event.severity)}
              </span>
            </div>
          )}
        </div>
        <div
          className="flex shrink-0 rounded-lg overflow-hidden"
          style={{ border: '1px solid var(--border-medium)' }}
          role="group"
          aria-label="Log detail mode"
        >
          {(['simple', 'advanced', 'raw'] as ActivityLogMode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className="px-2 py-1 text-[10px] font-medium transition-colors"
              style={{
                background: mode === m ? 'var(--accent-muted-bg)' : 'transparent',
                color: mode === m ? 'var(--accent)' : 'var(--text-muted)',
              }}
            >
              {MODE_LABELS[m]}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-2 space-y-1.5">
        {mode === 'simple' && (
          <>
            <p>{event.summary}</p>
            {event.actionTaken && (
              <p style={{ color: 'var(--text-muted)' }}>{event.actionTaken}</p>
            )}
            {event.remediation?.nextStep && (
              <p style={{ color: '#86efac' }}>Next: {event.remediation.nextStep}</p>
            )}
          </>
        )}

        {mode === 'advanced' && (
          <>
            <p><span style={{ color: 'var(--text-dim)' }}>Impact:</span> {event.impact}</p>
            <p><span style={{ color: 'var(--text-dim)' }}>Action:</span> {event.actionTaken}</p>
            {event.cause && (
              <p>
                <span style={{ color: 'var(--text-dim)' }}>Likely cause:</span>{' '}
                {event.cause.summary}{' '}
                <span style={{ color: 'var(--text-muted)' }}>
                  ({confidenceDisplay(event.cause.confidenceLabel)})
                </span>
              </p>
            )}
            {event.source.ruleId && (
              <p className="font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                rule={event.source.ruleId} · {event.eventType}
              </p>
            )}
            {levels.evidence.length > 0 && (
              <ul className="mt-1 space-y-0.5 font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
                {levels.evidence.slice(0, 8).map((e) => (
                  <li key={`${e.label}:${e.value}`}>
                    {e.label}: {e.value}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}

        {mode === 'raw' && (
          <pre
            className="max-h-40 overflow-auto rounded-lg p-2 font-mono text-[10px] leading-relaxed"
            style={{ background: 'rgba(0,0,0,0.25)', color: 'var(--text-muted)' }}
          >
            {JSON.stringify(event.raw ?? event, null, 2)}
          </pre>
        )}
      </div>

      <button
        type="button"
        onClick={() => setExplainOpen((v) => !v)}
        className="mt-2 flex items-center gap-1.5 text-[11px] font-medium transition-colors"
        style={{ color: 'var(--accent)' }}
      >
        <HelpCircle className="h-3.5 w-3.5" strokeWidth={1.8} />
        Explain This
        {explainOpen
          ? <ChevronUp className="h-3 w-3" strokeWidth={1.8} />
          : <ChevronDown className="h-3 w-3" strokeWidth={1.8} />}
      </button>

      {explainOpen && (
        <div
          className="mt-2 rounded-lg px-2.5 py-2 space-y-1.5 text-[11px]"
          style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)' }}
        >
          <p><span style={{ color: 'var(--text-dim)' }}>Simple:</span> {levels.simple}</p>
          <p><span style={{ color: 'var(--text-dim)' }}>Technical:</span> {levels.technical}</p>
          {event.remediation && (
            <p style={{ color: '#86efac' }}>Safe next step: {event.remediation.nextStep}</p>
          )}
        </div>
      )}
    </div>
  )
}
