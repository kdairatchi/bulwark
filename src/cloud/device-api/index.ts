// Entrypoint: run the Bulwrk device API. `npm run cloud:dev` (via tsx).
// In-memory store for local dev; production swaps in PostgreSQL (see docs).

import { DeviceStore } from './store'
import { createDeviceApiServer } from './server'

const PORT = Number(process.env.DEVICE_API_PORT) || 8787
const store = new DeviceStore()
const server = createDeviceApiServer(store)

server.listen(PORT, () => {
  process.stdout.write(`Bulwrk device API listening on http://127.0.0.1:${PORT}\n`)
  process.stdout.write(`Dashboard token: ${store.dashboardToken()}\n`)
  if (store.canBootstrapDashboard()) {
    process.stdout.write('Dashboard bootstrap: GET /v1/dashboard-bootstrap (local/dev)\n')
  } else {
    process.stdout.write('Dashboard bootstrap: disabled (DASHBOARD_TOKEN set)\n')
  }
})
