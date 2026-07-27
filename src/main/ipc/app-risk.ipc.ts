import { ipcMain } from 'electron'
import { IPC } from '../../shared/channels'
import type { AppRiskReport } from '../../shared/risk'
import { getInstalledProgramsFull } from '../services/program-uninstaller'
import { buildAppRiskReport } from '../services/risk-engine'

// Local-first: application risk is assessed entirely on-device by the
// deterministic risk engine. No cloud call, no telemetry.
export function registerAppRiskIpc(): void {
  ipcMain.handle(IPC.APP_RISK_FETCH, async (): Promise<AppRiskReport> => {
    const programs = await getInstalledProgramsFull()
    return buildAppRiskReport(programs)
  })
}
