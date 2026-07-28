import { AnimatePresence, motion } from 'framer-motion'
import { cn } from '@/lib/utils'

export type FindingExplainPanelProps = {
  why: string[]
  recommended: string
  accent?: string
  whyTitle?: string
  recommendedTitle?: string
  confidencePct?: number | null
  familyLabel?: string | null
  className?: string
  /** When false, render static (parent already animates). Default true. */
  animate?: boolean
}

/**
 * Shared “Why + Recommended” panel used by App Risk, parent findings, malware, etc.
 */
export function FindingExplainPanel({
  why,
  recommended,
  accent = '#f59e0b',
  whyTitle = 'Why this matters',
  recommendedTitle = 'What to do',
  confidencePct = null,
  familyLabel = null,
  className,
  animate = true,
}: FindingExplainPanelProps) {
  const body = (
    <div className={cn('space-y-3 text-[12px]', className)}>
      {(familyLabel || confidencePct != null) && (
        <div className="flex flex-wrap items-center gap-2">
          {familyLabel && (
            <span
              className="rounded-full px-2.5 py-0.5 text-[11px] font-semibold"
              style={{ color: accent, background: `${accent}1a`, border: `1px solid ${accent}40` }}
            >
              {familyLabel}
            </span>
          )}
          {confidencePct != null && (
            <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
              Confidence {confidencePct}%
            </span>
          )}
        </div>
      )}

      <div>
        <p className="mb-1.5 font-semibold text-zinc-300">{whyTitle}</p>
        <ul className="space-y-1">
          {why.map((line, i) => (
            <li key={i} className="flex gap-2" style={{ color: 'var(--text-muted)' }}>
              <span style={{ color: accent }}>•</span>
              <span className="leading-relaxed">{line}</span>
            </li>
          ))}
        </ul>
      </div>

      <p className="rounded-lg px-3 py-2 leading-relaxed" style={{ background: 'var(--bg-hover-2)', color: '#e4e4e7' }}>
        <span className="font-semibold">{recommendedTitle}:</span> {recommended}
      </p>
    </div>
  )

  if (!animate) return body

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2 }}
      className="overflow-hidden"
    >
      {body}
    </motion.div>
  )
}

/** Animated expand wrapper for finding rows. */
export function FindingExpand({
  open,
  children,
  className,
}: {
  open: boolean
  children: React.ReactNode
  className?: string
}) {
  return (
    <AnimatePresence initial={false}>
      {open && (
        <motion.div
          key="expand"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.2 }}
          className={cn('overflow-hidden', className)}
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  )
}
