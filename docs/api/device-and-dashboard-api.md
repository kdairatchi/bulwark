# API Design — Bulwark Control Plane

> **Status: device API implemented (reference service).** A dependency-free
> Node/TypeScript reference implementation of the device side lives in
> `src/cloud/device-api/` — run it with `npm run cloud:dev` (defaults to
> `http://127.0.0.1:8787`). It implements pairing-code enrollment with
> per-device Ed25519 keys and **signed** requests (no shared API key), plus
> heartbeat / inventory / findings and the dashboard read views. A production
> deployment swaps the in-memory store for PostgreSQL and adds the remaining
> dashboard/command endpoints. Try it end-to-end with
> `node scripts/device-client-demo.mjs` while the server is running.
>
> Implemented endpoints: `POST /v1/pairing-codes`, `POST /v1/devices/enroll`,
> `POST /v1/devices/{id}/heartbeat|inventory|findings` (signed),
> `GET /v1/devices`, `GET /v1/devices/{id}`, `GET /v1/findings`.

## Device APIs (agent → cloud)

```
POST /v1/devices/enroll
POST /v1/devices/{id}/heartbeat
POST /v1/devices/{id}/inventory
POST /v1/devices/{id}/findings
POST /v1/devices/{id}/network-events
GET  /v1/devices/{id}/policy
GET  /v1/devices/{id}/commands
POST /v1/devices/{id}/commands/{commandId}/result
```

## Dashboard APIs (user → cloud)

```
GET  /v1/devices
GET  /v1/devices/{id}
GET  /v1/findings
POST /v1/findings/{id}/review
POST /v1/devices/{id}/scan
POST /v1/devices/{id}/isolate
GET  /v1/reports
POST /v1/breach-monitors
GET  /v1/audit-events
```

## Enrollment (short-lived pairing code)

```
Dashboard creates code → user enters code on device → device generates key pair →
cloud binds device public key to the account → code expires
```

**Do not ship a shared API key inside every application.** Each device gets its own
key pair; the cloud stores the public key (`device_keys`).

## Command envelope

Commands are signed, allowlisted, single-use, and expiring — see the
[threat model](../threat-model/README.md#remote-command-model) for the envelope and
the device-side verification steps.

## Finding statuses

`confirmed_affected · likely_affected · potential_match · not_exploitable ·
fixed · accepted_risk · false_positive · unknown`.

## Fleet hierarchy

```
Account → Locations (Home · Parents' house · Small business) → Devices
```

Supports both households and small MSP customers with the same model.
