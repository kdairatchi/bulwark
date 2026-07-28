# Roadmap — Bulwark

Bulwark is a **multi-phase program**, not a single deliverable. This file tracks the
phased plan. See [`docs/product/vision.md`](docs/product/vision.md) and
[`docs/architecture/overview.md`](docs/architecture/overview.md) for context.

## Phase 0 — De-brand & foundation  *(active cleanup)*

Phase 0 establishes a coherent public identity and a trustworthy project baseline.
It is complete when public metadata, packaging, visible UI copy, and documentation
all describe this repository consistently. Internal identifiers are deliberately
separate: changing IPC channels, storage paths, metric names, or CLI contracts
requires an explicit migration plan and backward-compatibility tests.

- [x] Replace upstream package metadata (`package.json` name/description/keywords).
- [x] Repoint repository URL, homepage, and issue tracker to this repository
      (`kdairatchi/bulwark`).
- [x] Rebrand packaging identity (`electron-builder.yml`: appId, productName,
      artifact/shortcut names) — security-critical NSIS fields left intact.
- [x] Repoint the update channel (electron-builder `publish` infers the new repo).
- [x] Neutralize upstream service references: `BULWARK_CLOUD_URL` env override with a
      non-resolving placeholder default; cloud features stay dormant/opt-in.
- [x] Rebrand the visible desktop name (window title, English UI strings, About).
- [x] Author foundation docs: product vision, architecture, threat model, privacy,
      API design.
- [x] Finish the visible in-app rename across the translated cloud locale bundles.
- [ ] **Follow-up (own PR):** audit and complete any full UI restyle after the final
      brand is selected.
- [ ] **Follow-up (own PR):** internal-identifier rename (IPC channels, storage dirs,
      Prometheus `kudu_` metric namespace, CLI binary name). These are API/data
      contracts asserted by tests and require careful migration.
- [ ] Choose a final, trademark-cleared brand and only then lock signing identities.

### Phase 0 exit criteria

- [x] Repository metadata and release links resolve to the active repository.
- [x] Installers and post-install scripts use the Bulwark packaging identity.
- [x] Visible English and translated UI copy uses the current codename.
- [ ] A separate migration proposal covers internal identifiers and data contracts.
- [ ] Naming and signing identities are approved after trademark review.

## Phase 1 — Stabilize the desktop agent  *(complete)*

Completed: dry-run cleanup paths, restore-point gates for destructive actions,
structured findings, elevated-command and IPC hardening, updater safeguards, and
desktop/remote scan smoke coverage. Cross-platform release builds remain a CI
responsibility and are tracked under Phase 6 validation.

## Phase 2 — Extract the security core

Split the reusable security engine (inventory, risk engine, policy engine) into
`packages/security-core` etc., ahead of the monorepo migration.

## Phase 3 — Cloud foundation

Auth, device registration/enrollment (pairing codes + per-device keys), device list,
security score, findings, alerts, scan requests, email breach checks, basic reports.

**Landed in `src/cloud/device-api/`:** pairing enroll, device telemetry, findings +
review/score, remote commands, policy/isolate, network events, **email breach
monitors** (HIBP stub/live — `GET|POST /v1/breach-monitors`, ack, refresh).

## Phase 4 — Android TV agent (first unique feature)  *(scaffold in progress)*

Compose TV UI (ten-foot design), device enrollment, app inventory, device legitimacy
check, sideloaded-app detection, permission risk analysis, APK certificate/hash
collection, `VpnService` DNS parsing + local blocklist, event batching, remote policy
sync, emergency isolation.

**Landed in `apps/android-tv/`:** Gradle multi-module project (`:core` JVM protocol
library + `:app` Leanback/Compose TV UI), pairing enroll, WorkManager command poller,
PackageManager inventory with APK/cert hashes + static surface (exported/debuggable/
targetSdk), posture findings, DnsGuard `VpnService` + local blocklist, remote policy
sync + emergency isolation, network-event batching, JVM demo (`:core:runAgentDemo`).

## Phase 5 — Vulnerability intelligence  *(in progress)*

- [x] Software inventory normalization and deterministic risk findings.
- [x] CISA KEV sync, matching, deduplication, and fix recommendations.
- [x] OSV adapter and optional bounded package queries.
- [x] EPSS enrichment for CVE/KEV/OSV/NVD findings.
- [x] Bounded NVD 2.0 CPE adapter for known product mappings.
- [ ] Expand product/vendor normalization without loose-name false positives.
- [ ] Add NVD cache/update workflow using last-modified windows and API-key support.
- [ ] Add vendor/distro advisories and version-range evaluator beyond NVD CPE data.
- [ ] Consolidate finding confidence, deduplication, and remediation evidence.

## Phase 6 — Public beta

20–50 testers, Windows first, 5+ Android TV boxes, multiple manufacturers. Measure:
false-positive rate, scan duration, CPU/memory/battery, blocked-legitimate rate,
failed remediations, enrollment failures, user comprehension.

---

## MVP scope

**Desktop:** existing cleaning features · software inventory · startup inventory ·
security posture report · basic CVE matching · malware scan · application risk
explanations · device enrollment · cloud result sync.

**Android TV:** device posture check · installed-app inventory · sideloaded-app
detection · permission risk analysis · APK certificate/hash collection · local DNS
threat blocking · simple traffic alerts · large-screen UI · cloud enrollment.

**Cloud:** authentication · device registration · device list · security score ·
findings · alerts · scan request · email breach check · basic reports.

## Explicitly postponed

Full remote shell · packet decryption · enterprise SSO · complex compliance
frameworks · automatic registry cleanup · full global VPN infrastructure · ML malware
classification · MSP white-labeling · custom MDM · remote desktop · self-hosting
(offer a Docker Compose edition later, not first).
