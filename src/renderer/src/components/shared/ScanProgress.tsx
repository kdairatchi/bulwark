import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn, formatBytes, formatNumber } from '@/lib/utils'

interface ScanProgressProps {
  status: 'scanning' | 'cleaning'
  progress: number
  currentPath?: string
  itemsFound?: number
  sizeFound?: number
  /** Plain-language “what’s happening” line (cleaner / Linux-friendly). */
  detail?: string
  /** Short category/surface nickname shown as a chip. */
  focus?: string
  className?: string
}

export function ScanProgress({
  status,
  progress,
  currentPath,
  itemsFound = 0,
  sizeFound = 0,
  detail,
  focus,
  className
}: ScanProgressProps) {
  const { t } = useTranslation('common')
  return (
    <div
      className={cn('rounded-2xl p-5', className)}
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      aria-live="polite"
    >
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2.5 min-w-0">
          <Loader2 className="h-4 w-4 shrink-0 animate-spin text-amber-400" aria-hidden="true" />
          <div className="min-w-0">
            <span className="text-[13px] font-medium text-zinc-200">
              {status === 'scanning' ? t('scanning') : t('cleaning')}
            </span>
            {focus && (
              <span
                className="ml-2 inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium"
                style={{ color: '#fbbf24', background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.28)' }}
              >
                {focus}
              </span>
            )}
          </div>
        </div>
        <span className="font-mono text-[12px] shrink-0" style={{ color: 'var(--text-muted)' }}>
          {Math.round(progress)}%
        </span>
      </div>

      {detail && (
        <p className="mb-3 text-[12px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          {detail}
        </p>
      )}

      {/* Track */}
      <div
        className="mb-3.5 h-[6px] overflow-hidden rounded-full"
        style={{ background: 'var(--bg-subtle-2)' }}
        role="progressbar"
        aria-valuenow={Math.round(progress)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${status === 'scanning' ? t('scanning') : t('cleaning')} ${Math.round(progress)}%`}
      >
        <div
          className="h-full rounded-full transition-all duration-300 ease-out"
          style={{
            width: `${progress}%`,
            background: 'linear-gradient(90deg, #f59e0b 0%, #d97706 100%)'
          }}
        />
      </div>

      {currentPath && (
        <p className="mb-2 truncate font-mono text-[11px]" style={{ color: 'var(--text-muted)' }}>
          {currentPath}
        </p>
      )}

      <div className="flex items-center gap-4 text-[12px]" style={{ color: 'var(--text-muted)' }}>
        <span>
          {status === 'cleaning' ? t('removedLabel') : t('foundLabel')}{' '}
          <span className="font-medium text-zinc-300">{formatNumber(itemsFound)}</span> {t('itemsUnit')}
        </span>
        <span style={{ color: 'var(--text-faint)' }}>|</span>
        <span>
          {status === 'cleaning' ? t('reclaimedLabel') : t('sizeLabel')}{' '}
          <span className="font-medium text-zinc-300">{formatBytes(sizeFound)}</span>
        </span>
      </div>
    </div>
  )
}
