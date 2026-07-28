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
>
> Implemented endpoints:
> - `POST /v1/pairing-codes`, `POST /v1/devices/enroll`
> - `POST /v1/devices/{id}/heartbeat|inventory|findings` (device-signed)
> - `GET /v1/devices`, `GET /v1/devices/{id}`, `GET /v1/findings`
> - `GET /v1/server-key`
> - `POST /v1/devices/{id}/commands` (dashboard enqueue)
> - `GET /v1/devices/{id}/commands` (device-signed poll)
> - `POST /v1/devices/{id}/commands/{commandId}/result` (device-signed)

## Device APIs (agent → cloud)

```
POST /v1/devices/enroll
POST /v1/devices/{id}/heartbeat
POST /v1/devices/{id}/inventory
POST /v1/devices/{id}/findings
POST /v1/devices/{id}/network-events          # planned
GET  /v1/devices/{id}/policy                  # planned
GET  /v1/devices/{id}/commands                # implemented (device-signed)
POST /v1/devices/{id}/commands/{commandId}/result  # implemented (device-signed)
GET  /v1/server-key                           # implemented (server Ed25519 public key)
```

## Dashboard APIs (user → cloud)

```
GET  /v1/devices
GET  /v1/devices/{id}
GET  /v1/findings
POST /v1/devices/{id}/commands                # implemented (enqueue allowlisted command)
POST /v1/findings/{id}/review                 # planned
POST /v1/devices/{id}/scan                    # planned (maps to RUN_*_SCAN command)
POST /v1/devices/{id}/isolate                 # planned
GET  /v1/reports                              # planned
POST /v1/breach-monitors                      # planned
GET  /v1/audit-events                         # planned
```

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
```

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

## Fleet hierarchy

```
Account → Locations (Home · Parents' house · Small business) → Devices
```

Supports both households and small MSP customers with the same model.
