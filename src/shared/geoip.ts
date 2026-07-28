// IP → country geolocation, used for country-based network rules
// ("restrict connections to certain countries"). Backed by the free DB-IP
// Lite country database (CC-BY 4.0 — attribution required).

export interface GeoipStatus {
  ready: boolean
  /** Number of IP ranges loaded. */
  ranges: number
  updatedAt: string | null
  attribution: string
}

export const GEOIP_ATTRIBUTION = 'IP geolocation by DB-IP (https://db-ip.com) — CC BY 4.0'
