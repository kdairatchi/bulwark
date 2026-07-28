/**
 * Optional public cloud dashboard URL for “open in browser” links.
 * Domain/email stay open — never hardcode a marketing host.
 *
 * Prefer Vite `import.meta.env.VITE_BULWRK_CLOUD_URL` when set for the renderer.
 * Placeholders (`cloud.invalid`, empty, upstream usekudu) → null.
 */
export function publicCloudDashboardUrl(path = ''): string | null {
  const env = (typeof import.meta !== 'undefined'
    && (import.meta as ImportMeta & { env?: Record<string, string> }).env) || {}
  const fromVite = env.VITE_BULWRK_CLOUD_URL || env.VITE_BULWARK_CLOUD_URL || ''
  const fromProcess = (typeof process !== 'undefined'
    && (process.env?.BULWRK_CLOUD_URL || process.env?.BULWARK_CLOUD_URL)) || ''
  const base = (fromVite || fromProcess).trim().replace(/\/$/, '')
  if (!base) return null
  if (/cloud\.invalid/i.test(base)) return null
  if (/usekudu\.com/i.test(base)) return null
  if (!/^https?:\/\//i.test(base)) return null
  if (!path) return base
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${base}${suffix}`
}

/** Open the configured cloud dashboard, or invoke onMissing when none is set. */
export function openPublicCloudDashboard(
  path = '',
  onMissing?: () => void,
): boolean {
  const url = publicCloudDashboardUrl(path)
  if (!url) {
    onMissing?.()
    return false
  }
  window.open(url, '_blank')
  return true
}
