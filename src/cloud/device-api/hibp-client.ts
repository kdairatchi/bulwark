// Have I Been Pwned (HIBP) client for email breach lookups.
// Stub mode is the default without an API key (local/dev & tests).

import { createHash } from 'node:crypto'

export interface HibpBreach {
  Name: string
  Title: string
  Domain: string
  BreachDate: string
  DataClasses: string[]
  PwnCount: number
  IsVerified: boolean
  IsSensitive: boolean
}

export type HibpLookupResult = {
  ok: boolean
  source: 'stub' | 'hibp' | 'error'
  breaches: HibpBreach[]
  error?: string
}

export interface HibpClient {
  lookupBreaches(email: string): Promise<HibpLookupResult>
}

export interface HibpClientOpts {
  apiKey?: string
  fetchImpl?: typeof fetch
  /** Force stub mode even when an API key is present. */
  stub?: boolean
  userAgent?: string
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const MAX_EMAIL_LEN = 254

const STUB_TRIGGER_RE = /pwned|breach|leaked/i
const STUB_DOMAIN_SUFFIX = '@hibp-test.bulwark.local'

const FIXTURE_ADOBE: HibpBreach = {
  Name: 'Adobe',
  Title: 'Adobe',
  Domain: 'adobe.com',
  BreachDate: '2013-10-04',
  DataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
  PwnCount: 152_445_165,
  IsVerified: true,
  IsSensitive: false,
}

const FIXTURE_LINKEDIN: HibpBreach = {
  Name: 'LinkedIn',
  Title: 'LinkedIn',
  Domain: 'linkedin.com',
  BreachDate: '2012-05-05',
  DataClasses: ['Email addresses', 'Passwords'],
  PwnCount: 164_611_595,
  IsVerified: true,
  IsSensitive: false,
}

/** Lowercase + trim; basic format check; max 254 chars. */
export function normalizeEmail(email: string): string | null {
  if (typeof email !== 'string') return null
  const normalized = email.trim().toLowerCase()
  if (!normalized || normalized.length > MAX_EMAIL_LEN) return null
  if (!EMAIL_RE.test(normalized)) return null
  return normalized
}

/** SHA-256 hex of a normalized email (for dedupe / lookup without storing plain text in prod). */
export function emailLookupHash(email: string): string {
  const normalized = normalizeEmail(email) ?? email.trim().toLowerCase()
  return createHash('sha256').update(normalized).digest('hex')
}

function stubBreachesFor(email: string): HibpBreach[] {
  const hit =
    STUB_TRIGGER_RE.test(email) || email.endsWith(STUB_DOMAIN_SUFFIX)
  if (!hit) return []
  // Alternating fixture set: emails containing "linkedin" get LinkedIn only;
  // otherwise Adobe (+ LinkedIn for stronger "pwned" signal).
  if (/linkedin/i.test(email)) return [FIXTURE_LINKEDIN]
  if (/adobe/i.test(email)) return [FIXTURE_ADOBE]
  return [FIXTURE_ADOBE, FIXTURE_LINKEDIN]
}

function useStubMode(opts: HibpClientOpts): boolean {
  if (opts.stub === true) return true
  const key = typeof opts.apiKey === 'string' ? opts.apiKey.trim() : ''
  return !key
}

/**
 * Create an HIBP breach lookup client.
 * Without an API key (or with `stub: true` / `HIBP_STUB`), returns fixture data.
 */
export function createHibpClient(opts: HibpClientOpts = {}): HibpClient {
  const stub = useStubMode(opts)
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  const userAgent = opts.userAgent ?? 'Bulwark-Device-API'
  const apiKey = typeof opts.apiKey === 'string' ? opts.apiKey.trim() : ''

  return {
    async lookupBreaches(email: string): Promise<HibpLookupResult> {
      const normalized = normalizeEmail(email)
      if (!normalized) {
        return { ok: false, source: 'error', breaches: [], error: 'invalid email' }
      }

      if (stub) {
        return { ok: true, source: 'stub', breaches: stubBreachesFor(normalized) }
      }

      const url =
        `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(normalized)}` +
        '?truncateResponse=false'

      try {
        const res = await fetchImpl(url, {
          method: 'GET',
          headers: {
            'hibp-api-key': apiKey,
            'user-agent': userAgent,
          },
        })
        if (res.status === 404) {
          return { ok: true, source: 'hibp', breaches: [] }
        }
        if (!res.ok) {
          return {
            ok: false,
            source: 'error',
            breaches: [],
            error: `HIBP HTTP ${res.status}`,
          }
        }
        const data = (await res.json()) as unknown
        const breaches = Array.isArray(data)
          ? data
              .map(parseHibpBreach)
              .filter((b): b is HibpBreach => b !== null)
          : []
        return { ok: true, source: 'hibp', breaches }
      } catch (err) {
        // Soft-fail for refresh paths: empty list + error source.
        return {
          ok: false,
          source: 'error',
          breaches: [],
          error: err instanceof Error ? err.message : 'HIBP network error',
        }
      }
    },
  }
}

function parseHibpBreach(raw: unknown): HibpBreach | null {
  if (!raw || typeof raw !== 'object') return null
  const o = raw as Record<string, unknown>
  if (typeof o.Name !== 'string' || !o.Name) return null
  return {
    Name: o.Name,
    Title: typeof o.Title === 'string' ? o.Title : o.Name,
    Domain: typeof o.Domain === 'string' ? o.Domain : '',
    BreachDate: typeof o.BreachDate === 'string' ? o.BreachDate : '',
    DataClasses: Array.isArray(o.DataClasses)
      ? o.DataClasses.filter((x): x is string => typeof x === 'string')
      : [],
    PwnCount: typeof o.PwnCount === 'number' ? o.PwnCount : 0,
    IsVerified: o.IsVerified === true,
    IsSensitive: o.IsSensitive === true,
  }
}

/** Build the default client from env (`HIBP_API_KEY`, `HIBP_STUB`). */
export function createHibpClientFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): HibpClient {
  const stubEnv = (env.HIBP_STUB ?? '').trim().toLowerCase()
  const forceStub = stubEnv === '1' || stubEnv === 'true'
  return createHibpClient({
    apiKey: env.HIBP_API_KEY,
    stub: forceStub || undefined,
  })
}
