// Entrypoint: run the Bulwark device API. `npm run cloud:dev` (via tsx).
// In-memory store for local dev; production swaps in PostgreSQL (see docs).

import { DeviceStore } from './store'
import { createDeviceApiServer } from './server'

const PORT = Number(process.env.DEVICE_API_PORT) || 8787
const store = new DeviceStore()
const server = createDeviceApiServer(store)

server.listen(PORT, () => {
  process.stdout.write(`Bulwark device API listening on http://127.0.0.1:${PORT}\n`)
})
