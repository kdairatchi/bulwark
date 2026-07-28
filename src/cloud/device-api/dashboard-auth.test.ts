import { describe, it, expect } from 'vitest'
import {
  authenticateDashboard, dashboardBootstrap, parseBearerToken,
} from './handlers'
import { DeviceStore } from './store'

describe('dashboard auth', () => {
  it('parses Bearer tokens', () => {
    expect(parseBearerToken('Bearer abc')).toBe('abc')
    expect(parseBearerToken('bearer xyz')).toBe('xyz')
    expect(parseBearerToken('Token abc')).toBeNull()
    expect(parseBearerToken(undefined)).toBeNull()
  })

  it('accepts a valid dashboard bearer token', () => {
    const store = new DeviceStore({ dashboardToken: 'secret-token', allowDashboardBootstrap: false })
    expect(authenticateDashboard(store, 'Bearer secret-token')).toEqual({ ok: true })
    expect(authenticateDashboard(store, 'Bearer wrong').ok).toBe(false)
    expect(authenticateDashboard(store, undefined).ok).toBe(false)
  })

  it('bootstraps only when allowed', () => {
    const open = new DeviceStore({ dashboardToken: 'dev-token', allowDashboardBootstrap: true })
    const boot = dashboardBootstrap(open)
    expect(boot.status).toBe(200)
    expect((boot.body as { token: string }).token).toBe('dev-token')

    const locked = new DeviceStore({ dashboardToken: 'prod-token', allowDashboardBootstrap: false })
    expect(dashboardBootstrap(locked).status).toBe(403)
  })

  it('auto-generates a bootstrapable token by default', () => {
    const prev = process.env.DASHBOARD_TOKEN
    delete process.env.DASHBOARD_TOKEN
    try {
      const store = new DeviceStore()
      expect(store.canBootstrapDashboard()).toBe(true)
      expect(store.dashboardToken().length).toBeGreaterThan(16)
    } finally {
      if (prev !== undefined) process.env.DASHBOARD_TOKEN = prev
    }
  })
})
