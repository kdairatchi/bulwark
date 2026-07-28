# Architecture Overview — Bulwark

This document describes the **target** architecture. The repository today contains the
**desktop endpoint agent** (the forked Kudu Electron app); everything else is planned
and tracked in [`ROADMAP.md`](../../ROADMAP.md).

## Components

| Component | Status | Stack |
|-----------|--------|-------|
| Desktop agent | **Exists** (this repo) | Electron, React 19, TypeScript, SQLite, YARA-X, systeminformation |
| Android agent | **Scaffold+** (`apps/android-tv`) | Kotlin, Jetpack Compose for TV, WorkManager, PackageManager inventory/posture, DnsGuard `VpnService` |
| Network sensor | Planned | Local DNS/connection inspection, blocklists, IP/domain reputation |
| Cloud control plane | Planned | Next.js dashboard, Go device/telemetry APIs, PostgreSQL, Redis, S3-compatible storage |

## Desktop agent (today)

Electron three-process separation (already present and to be preserved):

```
Renderer (React)          Preload                     Main process
No Node integration  →    Typed, allowlisted    →     Business orchestration
Strict CSP (prod)         contextBridge API           ipc/ · services/ · platform/ · rules/
                                                            ↓
                                                    OS APIs (scan, inventory, firewall)
```

Entry: `src/main/index.ts` routes `--cli` → `runCli()`, `--daemon` → `runDaemon()`,
else GUI. IPC contract lives in `src/shared/channels.ts` + the `window.kudu` preload
API. Cleaning targets are JSON rules under `rules/`.

### Planned evolution: Rust security sidecar

Move privileged / performance-sensitive work out of Node into a signed Rust service:

```
Electron UI  → authenticated local IPC →  Rust security service  →  OS APIs / firewall / process inventory / networking
```

## Target monorepo layout

The single-app repo will migrate to a monorepo. **This is a dedicated, high-risk
migration phase** (it touches all build config, CI, and paths) — not done yet.

```
platform/
├── apps/          desktop · android · web-dashboard · admin-console · docs
├── services/      api · auth · device-registry · telemetry-ingest ·
│                  threat-intelligence · vulnerability-service ·
│                  notification-service · reporting-service · command-service
├── packages/      security-core · device-schema · policy-engine · risk-engine ·
│                  ui · api-client · crypto · shared-types
├── infrastructure/ docker · terraform · migrations · monitoring
├── rules/         cleaner · yara · network · compliance · application-reputation
└── docs/          architecture · threat-model · privacy · api · product
```

## Network Guard & SPN

The desktop **Network Guard** (Portmaster-inspired) provides three on-device,
metadata-only capabilities today: a live **per-application connection monitor**
(each connection evaluated by the threat-indicator engine), a TCP **port scanner**
(`net.connect`, no root), and a **destination checker**. All of this is local-first
— it inspects destination/connection metadata, never packet payloads.

**SPN (Secure Private Network) — planned.** Inspired by Safing's SPN, this is a
multi-hop, onion-style encrypted overlay that routes each app's traffic through
independent relays so no single hop learns both identity and destination. It
requires dedicated relay infrastructure plus a hardened tunnel client (a natural
fit for the future Rust security sidecar), so it is intentionally on the roadmap
and surfaced in the UI as "Planned" rather than shipped half-built. Enforcement
(actually blocking a connection, not just flagging it) similarly depends on a
privileged local firewall integration and is sequenced with the sidecar work.

## Cloud stack (planned)

- **Frontend:** Next.js (TypeScript) dashboard.
- **Device APIs / telemetry ingest:** Go (efficient, strongly typed, concurrent).
- **Database:** PostgreSQL. **Cache/queues:** Redis. **Object storage:** S3-compatible.
- **Realtime:** WebSocket or SSE. **Auth:** managed provider initially. **Billing:** Stripe.
- **Observability:** OpenTelemetry.

## Detection & vulnerability pipelines

- **Network detection:** connection event → normalize → local cache → threat-feed
  correlation → behavioral context → confidence → allow/alert/block → upload minimal
  metadata. Feeds (licensing to be verified per source): CISA KEV, URLhaus, ThreatFox,
  abuse.ch, Spamhaus, OpenPhish, PhishTank, MalwareBazaar, Emerging Threats, OTX.
- **Vulnerability:** inventory → normalize publisher/product/version → identify
  ecosystem → candidate identifiers → match (NVD, OSV, GHSA, MSRC, vendor/distro
  advisories) → validate version range → EPSS + KEV enrichment → fix availability →
  practical risk. Risk ≠ raw CVSS (see [risk model](../threat-model/README.md#risk-scoring)).

## Data storage (planned core tables)

`users, organizations, memberships, locations, devices, device_keys,
device_heartbeats, device_inventory, applications, application_installations,
findings, finding_evidence, remediations, commands, command_results, network_events,
threat_indicators, vulnerabilities, application_vulnerabilities, breach_monitors,
breach_exposures, policies, policy_assignments, audit_events, notification_channels,
subscriptions`.
