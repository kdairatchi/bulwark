# Roadmap — Bulwark

Bulwark is a **multi-phase program**, not a single deliverable. This file tracks the
phased plan. See [`docs/product/vision.md`](docs/product/vision.md) and
[`docs/architecture/overview.md`](docs/architecture/overview.md) for context.

## Phase 0 — De-brand & foundation  *(in progress in this PR)*

- [x] Replace upstream package metadata (`package.json` name/description/keywords).
- [x] Repoint repository URL, homepage, and issue tracker off `AdventDevInc` /
      `usekudu.com` to the fork (`kdairatchi/kudu`).
- [x] Rebrand packaging identity (`electron-builder.yml`: appId, productName,
      artifact/shortcut names) — security-critical NSIS fields left intact.
- [x] Repoint the update channel (electron-builder `publish` infers the new repo).
- [x] Neutralize upstream service references: `BULWARK_CLOUD_URL` env override with a
      non-resolving placeholder default; cloud features stay dormant/opt-in.
- [x] Rebrand the visible desktop name (window title, English UI strings, About).
- [x] Author foundation docs: product vision, architecture, threat model, privacy,
      API design.
- [ ] **Follow-up (own PR):** finish the in-app rename across the remaining 29 locale
      bundles and any full UI restyle.
- [ ] **Follow-up (own PR):** internal-identifier rename (IPC channels, storage dirs,
      Prometheus `kudu_` metric namespace, CLI binary name). These are API/data
      contracts asserted by tests and require careful migration.
- [ ] Choose a final, trademark-cleared brand and only then lock signing identities.

## Phase 1 — Stabilize the desktop agent

Run all tests; build on Windows/Linux/macOS; review elevated commands, IPC, and the
updater; add a dry-run mode everywhere; require restore points before destructive
actions; introduce a structured findings model.

## Phase 2 — Extract the security core

Split the reusable security engine (inventory, risk engine, policy engine) into
`packages/security-core` etc., ahead of the monorepo migration.

## Phase 3 — Cloud foundation

Auth, device registration/enrollment (pairing codes + per-device keys), device list,
security score, findings, alerts, scan requests, email breach checks, basic reports.

## Phase 4 — Android TV agent (first unique feature)  *(scaffold in progress)*

Compose TV UI (ten-foot design), device enrollment, app inventory, device legitimacy
check, sideloaded-app detection, permission risk analysis, APK certificate/hash
collection, `VpnService` DNS parsing + local blocklist, event batching, remote policy
sync, emergency isolation.

**Landed in `apps/android-tv/`:** Gradle multi-module project (`:core` JVM protocol
library + `:app` Leanback/Compose TV UI), pairing enroll, WorkManager command poller,
PackageManager inventory + sideload heuristics, JVM demo (`:core:runAgentDemo`).

## Phase 5 — Vulnerability intelligence

Software normalization; OSV/NVD adapters; CISA KEV + EPSS enrichment; vendor/distro
advisory adapters; version-range evaluator; finding deduplication; fix-recommendation
engine.

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
