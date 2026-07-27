import { create } from 'zustand'
import type { AppRiskReport } from '@shared/risk'

type Status = 'idle' | 'loading' | 'done'

interface AppRiskState {
  report: AppRiskReport | null
  status: Status
  error: string | null
  scan: () => Promise<void>
}

export const useAppRiskStore = create<AppRiskState>((set) => ({
  report: null,
  status: 'idle',
  error: null,
  scan: async () => {
    set({ status: 'loading', error: null })
    try {
      const report = await window.kudu.appRiskFetch()
      set({ report, status: 'done' })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to assess application risk'
      set({ error: msg, status: 'done' })
    }
  },
}))
