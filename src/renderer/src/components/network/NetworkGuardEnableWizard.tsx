import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  ChevronLeft,
  ChevronRight,
  Lock,
  ShieldCheck,
  ShieldAlert,
  HeartPulse,
  X,
  Power,
} from 'lucide-react'
import { FindingExplainPanel } from '@/components/shared/FindingExplainPanel'
import { explainSecureDnsEnable } from '@/lib/network-guard-explain'

/**
 * First-enable wizard for Network Guard Secure DNS.
 * Matches EmergencyIsolateWizard / Onboarding step motion.
 */
export function NetworkGuardEnableWizard({
  open,
  busy,
  t,
  onClose,
  onConfirmStart,
}: {
  open: boolean
  busy: boolean
  t: (key: string, opts?: Record<string, unknown>) => string
  onClose: () => void
  /** Return false to stay on confirm step (start failed). */
  onConfirmStart: () => void | Promise<void> | boolean | Promise<boolean>
}) {
  const [step, setStep] = useState(0)
  const total = 4
  const explained = explainSecureDnsEnable()
  const accent = '#f59e0b'

  useEffect(() => {
    if (open) setStep(0)
  }, [open])

  if (!open) return null

  const titles = [
    t('enableWizardStepMeaningTitle'),
    t('enableWizardStepHappenTitle'),
    t('enableWizardStepConfirmTitle'),
    t('enableWizardStepDoneTitle'),
  ]

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.85)' }}
      role="dialog"
      aria-modal="true"
      aria-label={t('enableWizardTitle')}
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
          aria-label={t('enableWizardClose')}
        >
          <X className="h-4 w-4" />
        </button>

        <div className="mb-5 flex items-center gap-3 pr-8">
          <div
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
            style={{ background: `${accent}1a`, border: `1px solid ${accent}44` }}
          >
            <Lock className="h-5 w-5" style={{ color: accent }} strokeWidth={1.8} />
          </div>
          <div>
            <h3 className="text-[16px] font-semibold text-white">{t('enableWizardTitle')}</h3>
            <p className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              {t('enableWizardSubtitle')}
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
                whyTitle={t('enableWizardWhy')}
                recommendedTitle={t('enableWizardRecommended')}
                animate={false}
              />
            )}

            {step === 1 && (
              <div className="space-y-4 text-[12px]">
                <ImpactList
                  icon={Power}
                  title={t('enableWizardWhatHappens')}
                  items={explained.whatHappens}
                  color={accent}
                />
                <ImpactList
                  icon={HeartPulse}
                  title={t('enableWizardStillWorks')}
                  items={explained.stillWorks}
                  color="#4ade80"
                />
                <ImpactList
                  icon={ShieldAlert}
                  title={t('enableWizardEnforcement')}
                  items={explained.enforcementNotes}
                  color="#38bdf8"
                />
              </div>
            )}

            {step === 2 && (
              <div className="space-y-3">
                <p className="text-[13px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  {t('enableWizardConfirmBody')}
                </p>
                <div
                  className="rounded-xl px-4 py-3 text-[12px]"
                  style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.28)', color: '#fde68a' }}
                >
                  <div className="flex items-start gap-2">
                    <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5" strokeWidth={1.8} />
                    <span>{t('enableWizardConfirmHint')}</span>
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
                  {t('enableWizardDoneBody')}
                </p>
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        <div className="mt-6 flex items-center justify-between gap-2">
          <div className="flex gap-2">
            {step > 0 && step < total - 1 && (
              <GhostButton onClick={() => setStep((s) => s - 1)} disabled={busy}>
                <ChevronLeft className="h-3.5 w-3.5" />{t('enableWizardBack')}
              </GhostButton>
            )}
            {step === 0 && (
              <GhostButton onClick={onClose} disabled={busy}>{t('enableWizardCancel')}</GhostButton>
            )}
          </div>

          <div className="flex gap-2">
            {step < 2 && (
              <PrimaryButton accent={accent} onClick={() => setStep((s) => s + 1)}>
                {t('enableWizardContinue')} <ChevronRight className="h-3.5 w-3.5" />
              </PrimaryButton>
            )}
            {step === 2 && (
              <PrimaryButton
                accent={accent}
                disabled={busy}
                onClick={async () => {
                  const result = await onConfirmStart()
                  if (result === false) return
                  setStep(total - 1)
                }}
              >
                {busy ? t('enableWizardWorking') : t('enableWizardConfirmAction')}
              </PrimaryButton>
            )}
            {step === total - 1 && (
              <PrimaryButton accent={accent} onClick={onClose}>
                {t('enableWizardDone')}
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
  icon: typeof Power
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
