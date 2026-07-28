import { useEffect, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import {
  ChevronLeft,
  ChevronRight,
  Link,
  Unlink,
  RefreshCw,
  Smartphone,
  KeyRound,
  HeartPulse,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'

type PairingStatus = {
  enrolled: boolean
  deviceId: string | null
  baseUrl: string | null
  lastHeartbeatAt: string | null
  lastCommandAt: string | null
  lastCommandType: string | null
  lastError: string | null
  commandsProcessed: number
} | null

const TOTAL_STEPS = 4

/**
 * Guided family-device pairing wizard (mint/enter code → enroll → heartbeat → first scan hint).
 * Matches Onboarding motion language (step slide + accent dots).
 */
export function FamilyPairingWizard({
  t,
  status,
  pairingCode,
  pairingBaseUrl,
  pairingEnrolling,
  onCodeChange,
  onBaseUrlChange,
  onEnroll,
  onUnenroll,
  onPollNow,
  onRequestFirstScan,
}: {
  t: (key: string, opts?: Record<string, unknown>) => string
  status: PairingStatus
  pairingCode: string
  pairingBaseUrl: string
  pairingEnrolling: boolean
  onCodeChange: (v: string) => void
  onBaseUrlChange: (v: string) => void
  onEnroll: () => void
  onUnenroll: () => void
  onPollNow: () => void
  onRequestFirstScan?: () => void
}) {
  const [step, setStep] = useState(0)
  const [advancedOpen, setAdvancedOpen] = useState(false)

  useEffect(() => {
    if (status?.enrolled) setStep(3)
  }, [status?.enrolled])

  useEffect(() => {
    if (pairingEnrolling) setStep(2)
  }, [pairingEnrolling])

  if (status?.enrolled) {
    return (
      <div
        className="rounded-2xl p-6 mb-4 mt-4"
        style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
      >
        <div className="flex items-start gap-3 mb-4">
          <div
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
            style={{ background: 'rgba(34,197,94,0.12)', border: '1px solid rgba(34,197,94,0.35)' }}
          >
            <ShieldCheck className="h-5 w-5" style={{ color: '#22c55e' }} strokeWidth={1.8} />
          </div>
          <div>
            <h3 className="text-[15px] font-semibold text-white">{t('pairingWizardEnrolledTitle')}</h3>
            <p className="text-[12px] mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {t('pairingWizardEnrolledDesc')}
            </p>
          </div>
        </div>

        <div className="space-y-1.5 text-[13px] mb-4" style={{ color: 'var(--text-secondary)' }}>
          <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingDeviceId')}: </span>{status.deviceId}</div>
          <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingHeartbeat')}: </span>{status.lastHeartbeatAt || t('statusLoading')}</div>
          <div><span style={{ color: 'var(--text-muted)' }}>{t('pairingLastCommand')}: </span>
            {status.lastCommandType ? `${status.lastCommandType} @ ${status.lastCommandAt}` : '—'}
          </div>
          {status.lastError && (
            <div className="text-red-400 text-[12px] mt-1">{status.lastError}</div>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          {onRequestFirstScan && (
            <button
              onClick={onRequestFirstScan}
              className="flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium"
              style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
            >
              <Sparkles className="h-3.5 w-3.5" strokeWidth={1.8} />
              {t('pairingWizardFirstScan')}
            </button>
          )}
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
    )
  }

  return (
    <div
      className="rounded-2xl p-6 mb-4 mt-4"
      style={{ background: 'var(--card-bg)', border: '1px solid var(--border-default)' }}
    >
      <h3 className="text-[15px] font-semibold text-white mb-1">{t('pairingWizardTitle')}</h3>
      <p className="text-[12px] mb-5" style={{ color: 'var(--text-muted)' }}>{t('pairingWizardSubtitle')}</p>

      <AnimatePresence mode="wait">
        {step === 0 && (
          <Step key="intro">
            <IconWell icon={Smartphone} color="#38bdf8" />
            <h4 className="text-[14px] font-semibold text-zinc-100 mb-1.5">{t('pairingWizardStepIntroTitle')}</h4>
            <p className="text-[13px] leading-relaxed mb-4" style={{ color: 'var(--text-muted)' }}>
              {t('pairingWizardStepIntroBody')}
            </p>
            <ul className="space-y-2 mb-5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
              <li className="flex gap-2"><span style={{ color: 'var(--accent)' }}>1.</span>{t('pairingWizardStepIntroBullet1')}</li>
              <li className="flex gap-2"><span style={{ color: 'var(--accent)' }}>2.</span>{t('pairingWizardStepIntroBullet2')}</li>
              <li className="flex gap-2"><span style={{ color: 'var(--accent)' }}>3.</span>{t('pairingWizardStepIntroBullet3')}</li>
            </ul>
            <PrimaryButton onClick={() => setStep(1)}>{t('pairingWizardContinue')}</PrimaryButton>
          </Step>
        )}

        {step === 1 && (
          <Step key="code">
            <IconWell icon={KeyRound} color="#f59e0b" />
            <h4 className="text-[14px] font-semibold text-zinc-100 mb-1.5">{t('pairingWizardStepCodeTitle')}</h4>
            <p className="text-[13px] leading-relaxed mb-4" style={{ color: 'var(--text-muted)' }}>
              {t('pairingWizardStepCodeBody')}
            </p>
            <input
              type="text"
              value={pairingCode}
              onChange={(e) => onCodeChange(e.target.value.toUpperCase())}
              onKeyDown={(e) => e.key === 'Enter' && pairingCode.trim().length >= 4 && setStep(2)}
              placeholder={t('pairingCodePlaceholder')}
              className="w-full rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700 tracking-widest mb-3"
              style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
              autoFocus
            />
            <button
              type="button"
              onClick={() => setAdvancedOpen((o) => !o)}
              className="text-[11px] mb-2"
              style={{ color: 'var(--text-dim)' }}
            >
              {advancedOpen ? t('pairingWizardHideAdvanced') : t('pairingWizardShowAdvanced')}
            </button>
            <AnimatePresence initial={false}>
              {advancedOpen && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden mb-3"
                >
                  <input
                    type="text"
                    value={pairingBaseUrl}
                    onChange={(e) => onBaseUrlChange(e.target.value)}
                    placeholder={t('pairingBaseUrlPlaceholder')}
                    className="w-full rounded-xl px-4 py-2.5 text-[13px] text-zinc-300 outline-none placeholder:text-zinc-700"
                    style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-medium)' }}
                  />
                </motion.div>
              )}
            </AnimatePresence>
            <div className="flex gap-2">
              <GhostButton onClick={() => setStep(0)}><ChevronLeft className="h-3.5 w-3.5" />{t('pairingWizardBack')}</GhostButton>
              <PrimaryButton
                disabled={pairingCode.trim().length < 4}
                onClick={() => setStep(2)}
              >
                {t('pairingWizardContinue')} <ChevronRight className="h-3.5 w-3.5" />
              </PrimaryButton>
            </div>
          </Step>
        )}

        {step === 2 && (
          <Step key="enroll">
            <IconWell icon={HeartPulse} color="#a78bfa" pulse={pairingEnrolling} />
            <h4 className="text-[14px] font-semibold text-zinc-100 mb-1.5">{t('pairingWizardStepEnrollTitle')}</h4>
            <p className="text-[13px] leading-relaxed mb-4" style={{ color: 'var(--text-muted)' }}>
              {pairingEnrolling ? t('pairingWizardStepEnrollWorking') : t('pairingWizardStepEnrollBody')}
            </p>
            <div className="flex gap-2">
              <GhostButton onClick={() => setStep(1)} disabled={pairingEnrolling}>
                <ChevronLeft className="h-3.5 w-3.5" />{t('pairingWizardBack')}
              </GhostButton>
              <PrimaryButton
                disabled={pairingEnrolling || pairingCode.trim().length < 4}
                onClick={onEnroll}
              >
                <Link className="h-3.5 w-3.5" strokeWidth={1.8} />
                {pairingEnrolling ? t('pairingEnrolling') : t('pairingEnroll')}
              </PrimaryButton>
            </div>
          </Step>
        )}

        {step === 3 && (
          <Step key="done">
            <IconWell icon={ShieldCheck} color="#22c55e" />
            <h4 className="text-[14px] font-semibold text-zinc-100 mb-1.5">{t('pairingWizardStepDoneTitle')}</h4>
            <p className="text-[13px] leading-relaxed mb-4" style={{ color: 'var(--text-muted)' }}>
              {t('pairingWizardStepDoneBody')}
            </p>
          </Step>
        )}
      </AnimatePresence>

      <div className="mt-6 flex justify-center gap-2">
        {Array.from({ length: TOTAL_STEPS }, (_, i) => (
          <div
            key={i}
            className="h-1.5 rounded-full transition-all duration-300"
            style={{
              width: i === step ? 24 : 8,
              background: i === step ? 'var(--accent)' : i < step ? 'rgba(245,158,11,0.45)' : 'var(--bg-active)',
            }}
          />
        ))}
      </div>
    </div>
  )
}

function Step({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.2 }}
    >
      {children}
    </motion.div>
  )
}

function IconWell({
  icon: Icon,
  color,
  pulse,
}: {
  icon: typeof Smartphone
  color: string
  pulse?: boolean
}) {
  return (
    <div
      className={`mb-4 flex h-12 w-12 items-center justify-center rounded-xl ${pulse ? 'animate-pulse' : ''}`}
      style={{ background: `${color}1a`, border: `1px solid ${color}44` }}
    >
      <Icon className="h-5 w-5" style={{ color }} strokeWidth={1.8} />
    </div>
  )
}

function PrimaryButton({
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
      className="inline-flex items-center gap-1.5 rounded-xl px-4 py-2.5 text-[13px] font-medium transition-colors disabled:opacity-40"
      style={{ background: 'var(--accent)', color: 'var(--text-on-accent)' }}
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
