import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  HeartPulse,
  X,
  Globe,
} from 'lucide-react'
import { FindingExplainPanel } from '@/components/shared/FindingExplainPanel'
import { explainSecureDnsEnforce } from '@/lib/network-guard-explain'

/**
 * Confirm wizard for system-wide Secure DNS enforcement (Protect this device).
 */
export function NetworkGuardEnforceWizard({
  open,
  busy,
  resolverAddress,
  t,
  onClose,
  onConfirmEnable,
}: {
  open: boolean
  busy: boolean
  resolverAddress?: string | null
  t: (key: string, opts?: Record<string, unknown>) => string
  onClose: () => void
  onConfirmEnable: () => void | Promise<void> | boolean | Promise<boolean>
}) {
  const [step, setStep] = useState(0)
  const total = 4
  const explained = explainSecureDnsEnforce(resolverAddress || undefined)
  const accent = '#22c55e'

  useEffect(() => {
    if (open) setStep(0)
  }, [open])

  if (!open) return null

  const titles = [
    t('enforceWizardStepMeaningTitle'),
    t('enforceWizardStepHappenTitle'),
    t('enforceWizardStepConfirmTitle'),
    t('enforceWizardStepDoneTitle'),
  ]

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.85)' }}
      role="dialog"
      aria-modal="true"
      aria-label={t('enforceWizardTitle')}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.25 }}
        className="relative w-full max-w-lg rounded-2xl p-7"
        style={{ background: 'var(--card-bg)', border: '1px solid var(--border-medium)' }}
      >
        <button
          type="button"
          onClick={onClose}
          disabled={busy}
          className="absolute right-4 top-4 rounded-lg p-1.5 disabled:opacity-40"
          style={{ color: 'var(--text-muted)' }}
          aria-label={t('enforceWizardClose')}
        >
          <X className="h-4 w-4" />
        </button>

        <div className="mb-5 flex items-center gap-3 pr-8">
          <div
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
            style={{ background: `${accent}1a`, border: `1px solid ${accent}44` }}
          >
            <Globe className="h-5 w-5" style={{ color: accent }} strokeWidth={1.8} />
          </div>
          <div>
            <h3 className="text-[16px] font-semibold text-white">{t('enforceWizardTitle')}</h3>
            <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              {t('enforceWizardSubtitle')}
            </p>
          </div>
        </div>

        <AnimatePresence mode="wait">
          <motion.div
            key={step}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.2 }}
          >
            <h4 className="text-[14px] font-semibold text-zinc-100 mb-2">{titles[step]}</h4>

            {step === 0 && (
              <FindingExplainPanel
                why={explained.why}
                recommended={explained.recommended}
                accent={accent}
                whyTitle={t('enforceWizardWhy')}
                recommendedTitle={t('enforceWizardRecommended')}
                animate={false}
              />
            )}

            {step === 1 && (
              <div className="space-y-4 text-[12px]">
                <ImpactList
                  icon={Globe}
                  title={t('enforceWizardWhatHappens')}
                  items={explained.whatHappens}
                  color={accent}
                />
                <ImpactList
                  icon={HeartPulse}
                  title={t('enforceWizardStillWorks')}
                  items={explained.stillWorks}
                  color="#4ade80"
                />
                <ImpactList
                  icon={ShieldAlert}
                  title={t('enforceWizardRisks')}
                  items={explained.risks}
                  color="#fbbf24"
                />
              </div>
            )}

            {step === 2 && (
              <div className="space-y-3">
                <p className="text-[13px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  {t('enforceWizardConfirmBody')}
                </p>
                <div
                  className="rounded-xl px-4 py-3 text-[12px]"
                  style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.28)', color: '#bbf7d0' }}
                >
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" strokeWidth={1.8} />
                    <span>{t('enforceWizardConfirmHint')}</span>
                  </div>
                </div>
              </div>
            )}

            {step === 3 && (
              <div className="text-center py-2">
                <div
                  className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl"
                  style={{ background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.35)' }}
                >
                  <ShieldCheck className="h-7 w-7" style={{ color: '#22c55e' }} strokeWidth={1.8} />
                </div>
                <p className="text-[13px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  {t('enforceWizardDoneBody')}
                </p>
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        <div className="mt-6 flex items-center justify-between gap-2">
          <div className="flex gap-2">
            {step > 0 && step < total - 1 && (
              <GhostButton onClick={() => setStep((s) => s - 1)} disabled={busy}>
                <ChevronLeft className="h-3.5 w-3.5" />{t('enforceWizardBack')}
              </GhostButton>
            )}
            {step === 0 && (
              <GhostButton onClick={onClose} disabled={busy}>{t('enforceWizardCancel')}</GhostButton>
            )}
          </div>

          <div className="flex gap-2">
            {step < 2 && (
              <PrimaryButton accent={accent} onClick={() => setStep((s) => s + 1)}>
                {t('enforceWizardContinue')} <ChevronRight className="h-3.5 w-3.5" />
              </PrimaryButton>
            )}
            {step === 2 && (
              <PrimaryButton
                accent={accent}
                disabled={busy}
                onClick={async () => {
                  const result = await onConfirmEnable()
                  if (result === false) return
                  setStep(total - 1)
                }}
              >
                {busy ? t('enforceWizardWorking') : t('enforceWizardConfirmAction')}
              </PrimaryButton>
            )}
            {step === total - 1 && (
              <PrimaryButton accent={accent} onClick={onClose}>
                {t('enforceWizardDone')}
              </PrimaryButton>
            )}
          </div>
        </div>

        <div className="mt-5 flex justify-center gap-2">
          {Array.from({ length: total }, (_, i) => (
            <div
              key={i}
              className="h-1.5 rounded-full transition-all duration-300"
              style={{
                width: i === step ? 24 : 8,
                background: i === step ? accent : i < step ? `${accent}73` : 'var(--bg-active)',
              }}
            />
          ))}
        </div>
      </motion.div>
    </div>
  )
}

function ImpactList({
  icon: Icon,
  title,
  items,
  color,
}: {
  icon: typeof Globe
  title: string
  items: string[]
  color: string
}) {
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5 text-[12px] font-semibold text-zinc-300">
        <Icon className="h-3.5 w-3.5" style={{ color }} strokeWidth={1.8} />
        {title}
      </div>
      <ul className="space-y-1">
        {items.map((line, i) => (
          <li key={i} className="flex gap-2" style={{ color: 'var(--text-muted)' }}>
            <span style={{ color }}>•</span>
            <span className="leading-relaxed">{line}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function PrimaryButton({
  children,
  onClick,
  disabled,
  accent,
}: {
  children: React.ReactNode
  onClick: () => void
  disabled?: boolean
  accent: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium transition-colors disabled:opacity-40"
      style={{ background: accent, color: '#111' }}
    >
      {children}
    </button>
  )
}

function GhostButton({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium disabled:opacity-40"
      style={{ border: '1px solid var(--border-medium)', color: 'var(--text-secondary)' }}
    >
      {children}
    </button>
  )
}
