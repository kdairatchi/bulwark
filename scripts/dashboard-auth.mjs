/** Shared helper: fetch local/dev dashboard bearer token via bootstrap. */
export async function fetchDashboardToken(baseUrl) {
  const BASE = baseUrl.replace(/\/+$/, '')
  const res = await fetch(`${BASE}/v1/dashboard-bootstrap`)
  if (!res.ok) {
    throw new Error(`dashboard bootstrap failed: HTTP ${res.status} (set DASHBOARD_TOKEN or enable bootstrap)`)
  }
  const body = await res.json()
  if (!body.token) throw new Error('dashboard bootstrap missing token')
  return body.token
}

export function dashboardAuthHeaders(token) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  }
}
