# API Design — Bulwark Control Plane

> **Status: device API + secure remote commands implemented (reference service).**
> A dependency-free Node/TypeScript reference implementation lives in
> `src/cloud/device-api/` — run it with `npm run cloud:dev` (defaults to
> `http://127.0.0.1:8787`). It implements pairing-code enrollment with
> per-device Ed25519 keys and **signed** requests (no shared API key), plus
> heartbeat / inventory / findings, dashboard read views, and **server-signed,
> allowlisted, expiring remote commands**. A production deployment swaps the
> in-memory store for PostgreSQL and adds remaining dashboard endpoints.
>
> Try it end-to-end:
> - Device telemetry: `node scripts/device-client-demo.mjs`
> - Remote commands: `node scripts/command-demo.mjs`
> - Desktop agent flow: `node scripts/device-agent-demo.mjs`
> - Android TV agent core (JVM): `cd apps/android-tv && ./gradlew :core:runAgentDemo`
> - Policy + emergency isolate: `node scripts/policy-isolate-demo.mjs`
> - Event batch ingest: `node scripts/events-batch-demo.mjs`
> - Finding review + score: `node scripts/finding-review-demo.mjs`
> - Email breach monitors (stub HIBP): `node scripts/breach-monitor-demo.mjs`
>
> The Electron app exposes pairing enroll / poll / status on the Cloud page
> (`deviceCommandAgent` in `src/main/services/device-command-agent.ts`).
> The Android TV agent lives in `apps/android-tv/` (Compose TV UI + WorkManager).
>
> Dashboard **writes** require `Authorization: Bearer <token>`. Local `cloud:dev`
> auto-generates a token (printed on startup) and allows
> `GET /v1/dashboard-bootstrap`. Set `DASHBOARD_TOKEN` to supply a fixed token
> and disable bootstrap.
>
> Implemented endpoints:
> - `POST /v1/pairing-codes` (dashboard auth), `POST /v1/devices/enroll`
> - `GET /v1/dashboard-bootstrap` (local/dev only)
> - `POST /v1/devices/{id}/heartbeat|inventory|findings` (device-signed)
> - `GET /v1/devices`, `GET /v1/devices/{id}`, `GET /v1/findings`, `GET /v1/network-events` (dashboard auth)
> - `GET /v1/server-key` (public)
> - `POST /v1/devices/{id}/commands` (dashboard auth) · `GET …/commands` · `POST …/commands/{id}/result`
> - `GET /v1/devices/{id}/policy` (device-signed) · `PUT …/policy` (dashboard auth)
> - `POST /v1/devices/{id}/isolate` · `DELETE …/isolate` (dashboard auth)
> - `POST /v1/devices/{id}/network-events` (device-signed)
> - `GET|POST /v1/breach-monitors` · `DELETE …/{email}` · `POST …/acknowledge` · `POST …/refresh` (dashboard auth; stub HIBP without key)

## Device APIs (agent → cloud)

```
POST /v1/devices/enroll
POST /v1/devices/{id}/heartbeat
POST /v1/devices/{id}/inventory
POST /v1/devices/{id}/findings
POST /v1/devices/{id}/network-events          # implemented (device-signed event batch)
GET  /v1/devices/{id}/policy                  # implemented (device-signed)
GET  /v1/devices/{id}/commands                # implemented (device-signed)
POST /v1/devices/{id}/commands/{commandId}/result  # implemented (device-signed)
GET  /v1/server-key                           # implemented (server Ed25519 public key)
```

## Dashboard APIs (user → cloud)

All of these require `Authorization: Bearer <dashboard-token>` unless noted.

```
GET  /v1/devices                              # Bearer
GET  /v1/devices/{id}                         # Bearer
GET  /v1/findings                             # Bearer
GET  /v1/network-events                       # Bearer
POST /v1/devices/{id}/commands                # Bearer (enqueue allowlisted command)
PUT  /v1/devices/{id}/policy                  # Bearer (merge policy + APPLY_POLICY command)
POST /v1/devices/{id}/isolate                 # Bearer (emergency isolate + ISOLATE_DEVICE)
DELETE /v1/devices/{id}/isolate               # Bearer (clear + CLEAR_ISOLATION)
POST /v1/findings/{id}/review                 # Bearer (status=false_positive|accepted_risk|…)
POST /v1/devices/{id}/scan                    # Bearer (kind=health|malware|vulnerability|lolbins → RUN_*)
GET  /v1/breach-monitors                      # Bearer (list monitors + exposures)
POST /v1/breach-monitors                      # Bearer ({ email } — add + HIBP/stub lookup)
DELETE /v1/breach-monitors/{email}            # Bearer (URL-encoded email)
POST /v1/breach-monitors/acknowledge          # Bearer ({ breachIds: string[] })
POST /v1/breach-monitors/refresh              # Bearer (optional { email } — re-check one or all)
GET  /v1/reports                              # planned
GET  /v1/audit-events                         # planned
```

## Email breach monitors

Account-scoped monitors (no multi-tenant yet) backed by Have I Been Pwned.

| Mode | When | Behavior |
|------|------|----------|
| **Stub** | No `HIBP_API_KEY`, or `HIBP_STUB=1`/`true` | Emails matching `/pwned\|breach\|leaked/i` or ending `@hibp-test.bulwark.local` return Adobe/LinkedIn-style fixtures; others return `[]` |
| **Live** | `HIBP_API_KEY` set (and stub not forced) | `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false` with `hibp-api-key` + `user-agent: Bulwark-Device-API`. 404 → no breaches. Network errors soft-fail. |

Response shape matches desktop `BreachMonitorResult`: `{ emails: [{ email, lastCheckedAt, fresh, monitoringPaused, breaches: [{ id, name, title, domain, breachDate, dataClasses, pwnCount, isVerified, isSensitive, acknowledgedAt }] }], limit, usage }`. Limit is **10** monitors. `fresh` is true when `lastCheckedAt` is within 24h.

**Reference store note:** the in-memory store keeps the **normalized email in plaintext** for demos; production must encrypt at rest (see [privacy](../privacy/README.md#breach-monitoring-privacy)) and retain only a lookup hash for dedupe.

Create responses also include `source` (`stub` \| `hibp` \| `error`) and `created` (boolean).
## Enrollment (short-lived pairing code)

```
Dashboard creates code → user enters code on device → device generates key pair →
cloud binds device public key to the account → code expires
```

**Do not ship a shared API key inside every application.** Each device gets its own
key pair; the cloud stores the public key (`device_keys`).

## Device request authentication

Authenticated device routes require headers:

| Header | Meaning |
|--------|---------|
| `X-Device-Id` | Enrolled device id |
| `X-Timestamp` | ISO-8601 issue time (≈5 min skew window) |
| `X-Signature` | Base64 Ed25519 signature over `METHOD\nPATH\nTIMESTAMP\nSHA256(body)` |

Unsigned, tampered, stale, or unknown-device requests are rejected.

## Secure remote commands

Commands are **server-signed**, **allowlisted**, **expiring**, and **nonce-protected**.
See the [threat model](../threat-model/README.md#remote-command-model).

### Allowlist (v1)

```
REQUEST_INVENTORY
RUN_MALWARE_SCAN
RUN_VULNERABILITY_SCAN
RUN_HEALTH_ASSESSMENT
UPDATE_THREAT_FEEDS
QUARANTINE_FILE
BLOCK_DOMAIN
RESTART_AGENT
ISOLATE_DEVICE
CLEAR_ISOLATION
APPLY_POLICY
```

**Desktop enforcement (non-stub):**

| Command | Behavior |
|---------|----------|
| `UPDATE_THREAT_FEEDS` | Syncs enabled filter lists (URLhaus by default) into the local DoT blocklist; optional `domains[]` (+ `replace`) merges into remote blocks (Android-parity). Params: `syncLists` (default true), `listIds[]`, `domains[]`, `replace`. |
| `QUARANTINE_FILE` | Moves `path` / `paths[]` into the app quarantine folder when under platform malware allowlist (`/tmp`, Downloads, …). |
| `RESTART_AGENT` | Returns `{ ok, scheduled: true }` immediately, then relaunches the Electron process via `app.relaunch` + `app.exit(0)` after ~1s so the command result can be posted first. |

**Android TV enforcement (non-stub):**

| Command | Behavior |
|---------|----------|
| `QUARANTINE_FILE` | Moves `path` / `paths[]` into `filesDir/quarantine` when under app-scoped roots (`filesDir`, `cacheDir`, `externalFilesDir`) or readable public Downloads. Rejects path escapes; honest failures for missing/permission errors. |
| `RESTART_AGENT` | Returns `{ ok, scheduled: true }` immediately, then cancels/reschedules the unique periodic `AgentWorker` and enqueues a one-shot tick (`bulwark-device-agent-now`). Does **not** kill DnsGuard VPN or call `System.exit`. |
| `BLOCK_DOMAIN` / `ISOLATE_DEVICE` / `CLEAR_ISOLATION` / `APPLY_POLICY` / `UPDATE_THREAT_FEEDS` / inventory & scans | Enforced in `DeviceAgentService` (DNS Guard VpnService + blocklist / PackageManager posture). JVM demo stubs remain in `CommandExecutor.defaultExecute` when no Android `Context` is available. |

**Not allowed:** arbitrary shell / PowerShell / remote-exec (`RUN_SHELL` is rejected
at enqueue with HTTP 400).

### Envelope

```json
{
  "commandId": "cmd_…",
  "deviceId": "dev_…",
  "type": "RUN_MALWARE_SCAN",
  "parameters": { "scope": "quick" },
  "issuedAt": "…",
  "expiresAt": "…",
  "nonce": "…",
  "signature": "<base64 Ed25519 by server key over canonical string>"
}
```

Canonical string (newline-joined):

```
commandId
deviceId
type
JSON.stringify(parameters)
issuedAt
expiresAt
nonce
```

### Flow

1. Device fetches `GET /v1/server-key` once (caches the server public key).
2. Dashboard `POST /v1/devices/{id}/commands` with `{ type, parameters }` —
   server builds and signs the envelope (non-allowlisted types → 400).
3. Device `GET /v1/devices/{id}/commands` (device-signed) — receives pending envelopes.
4. Device verifies: server signature, allowlist, deviceId match, expiry, nonce replay.
5. Device executes locally, then `POST …/commands/{commandId}/result` (device-signed).
6. Forged (non-server) signatures and expired envelopes must be rejected **on device**
   even if somehow delivered.

Shared implementation: `src/cloud/device-api/commands.ts`
(`signCommand` / `verifyCommandEnvelope`).

## Finding statuses

`confirmed_affected · likely_affected · potential_match · not_exploitable ·
fixed · accepted_risk · false_positive · unknown`.

Findings may include an optional `category` (`kev`, `osv`, `technique`, `lolbin`,
`publisher`, …) and optional `fixRecommendation` (KEV `requiredAction` or
`Upgrade <app> to <vulnerableBelow> or newer`). Open findings are **deduped** on `(deviceId, subjectName, category)`
— re-submits refresh `level`/`reason`/`fixRecommendation` instead of creating duplicates.

`POST /v1/findings/{id}/review` (Bearer) body: `{ "status": "false_positive"|"accepted_risk"|"fixed"|"not_exploitable"|…, "note"?: "…" }`.

`GET /v1/devices` includes `securityScore` (0–100) and `openFindingsCount`. Resolved
statuses (`false_positive`, `accepted_risk`, `fixed`, `not_exploitable`) do not
penalize the score. Open findings are **category-weighted** (KEV/OSV/ransomware
penalize more than publisher noise).

## Fleet hierarchy

```
Account → Locations (Home · Parents' house · Small business) → Devices
```

Supports both households and small MSP customers with the same model.
