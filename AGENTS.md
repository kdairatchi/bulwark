# Agents

Instructions for all AI sub-agents (Claude Code agents, worktree agents, etc.) working on this codebase.

## Commit Conventions

Always use [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>(<scope>): <short summary>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.

Breaking changes must include `!` after the type/scope.

## Before Committing

- Run `npm test` to ensure all tests pass.
- Run `npm run validate:rules` if rule JSON files were changed.

## Code Style

- Follow existing patterns in the codebase.
- Keep PRs focused — one logical change per branch.

## Cursor Cloud specific instructions

Kudu is a single Electron desktop app (React 19 renderer + Node main process, built by electron-vite). There is no separate backend/frontend server. Commands (`npm run dev`, `npm test`, `npm run validate:rules`, `npm run build`) are documented in `CLAUDE.md` / `CONTRIBUTING.md`.

- Dependencies are refreshed by the startup update script (`npm install`); its `postinstall` runs `patch-package` and `electron-rebuild -w better-sqlite3`. If native modules misbehave after changing Electron/Node, re-run `npm install` to rebuild `better-sqlite3`.
- GUI: run `npm run dev` with `DISPLAY=:1` (the VM's X server). The Electron window then renders on that display and can be driven via computer use. On startup you'll see harmless `dbus/bus.cc` connection errors and a one-time `[yara] Updated rules` line — these are normal, not failures.
- Core "hello world" flow: sidebar `Cleaner` → `Scan` performs a real filesystem scan and lists recoverable temp/cache files. Since the VM runs unelevated, ~13 categories are skipped as "administrator privileges required" — expected; do NOT click "Relaunch as Admin" (it restarts the app).
- CLI/daemon modes (`--cli` / `--daemon`) are for headless use; launching the built `out/main/index.js` directly from a plain shell here can crash on X init. Use the GUI (`npm run dev` on `DISPLAY=:1`) for interactive verification.
- No ESLint/Prettier/tsc lint script exists; `npm run validate:rules` (rule JSON schema) and `npm test` (Vitest, ~2355 tests) are the quality gates.
- Two cloud paths exist: legacy Pusher/API-key agent (`cloudAgent`, `BULWARK_CLOUD_URL`) and the new pairing/Ed25519 device API (`deviceCommandAgent`, `DEVICE_API_URL`, default `http://127.0.0.1:8787`). Run the reference control plane with `npm run cloud:dev` (separate Node process — not part of Electron). Dashboard **read and write** routes (devices, findings, network-events, pairing, policy, isolate, commands, scan, review) require `Authorization: Bearer <token>`. Public exceptions: `POST /v1/devices/enroll`, `GET /v1/server-key`, and local-only `GET /v1/dashboard-bootstrap`. Local/dev auto-generates a token and exposes bootstrap; set `DASHBOARD_TOKEN` to disable bootstrap. Demos: `scripts/device-client-demo.mjs`, `scripts/command-demo.mjs`, `scripts/device-agent-demo.mjs`, `scripts/policy-isolate-demo.mjs`, `scripts/events-batch-demo.mjs`, `scripts/parent-dashboard-demo.mjs`, `npx tsx scripts/desktop-policy-agent-demo.mts`, `npx tsx scripts/desktop-inventory-demo.mts`. Parent UI lives on the Cloud page (`ParentControlPanel`) and talks to dashboard routes via IPC (`dashboard:*` channels), auto-bootstrapping the token when available. Desktop agent applies remote isolate/policy/block via the **loopback DoT resolver only** (`devicePolicyEnforcer`) — it does **not** rewrite `/etc/resolv.conf` (system-wide DNS remains a user action in Network Guard). Inventory sync posts installed apps + lightweight findings every ~5 minutes (and on `REQUEST_INVENTORY`). Parent can queue `POST /v1/devices/{id}/scan` (`kind=health|malware|vulnerability|lolbins`) which maps to `RUN_*`; the desktop agent runs bounded inventory/risk-engine posture scans plus offline LotL/technique/**vuln_heuristic** grep (`rules/security/lolbins.json`) and **KEV CVE matching** (`rules/security/kev.json`, optionally merged with a live CISA KEV cache via `kevSync=true`). Optional `osv=true` / `epss=true` add bounded OSV.dev + FIRST.org EPSS enrichment. Findings persist an optional `category` (`kev`/`osv`/`technique`/…); open findings dedupe by `(subjectName, category)`; `securityScore` weights KEV/OSV/ransomware higher than publisher noise. Full NVD CPE matching still incomplete — see `rules/security/README.md`. `UPDATE_THREAT_FEEDS` syncs enabled filter lists (URLhaus) into the loopback DoT blocklist (+ optional `domains[]`); `QUARANTINE_FILE` moves allowlisted paths via `quarantineMalware`. Parent UI: Refresh threat feeds / Quarantine file. Demo: `node scripts/threat-feeds-demo.mjs`. Demo: `node scripts/remote-scan-demo.mjs`. Findings can be reviewed via `POST /v1/findings/{id}/review` (`false_positive` / `accepted_risk` / …); `GET /v1/devices` exposes `securityScore` + `openFindingsCount`. Demo: `node scripts/finding-review-demo.mjs`. CI locks the isolate→tick→dns_blocked loop in `src/main/services/device-control-plane.e2e.test.ts`. Do not put a bare `cloud/` entry in `.gitignore` (use `/cloud/` only) or `src/cloud/` will be ignored.
- Android TV agent lives in `apps/android-tv/` (see its README). JVM protocol tests/demo need JDK 17+ only: `cd apps/android-tv && ./gradlew :core:test :core:runAgentDemo` with `cloud:dev` running (demo bootstraps dashboard Bearer token). APK builds need `ANDROID_HOME` / `local.properties` `sdk.dir`. Emulator → host control plane URL is `http://10.0.2.2:8787`. Remote isolate / DNS policy requires on-device `VpnService.prepare()` — until approved, command results use `applied: false` + `reason=vpn_permission_required`, inventory reports `dnsGuard.vpnConsentPending`, and the parent panel shows **VPN PENDING**.
- Activity & Logs foundation: shared schema in `src/shared/activity-event.ts`, explain helpers in `activity-explain.ts`, adapters in `activity-adapters.ts`. Parent alerts (Cloud page) and History → **Activity** tab render `ActivityEventCard` with Simple / Advanced / Raw + Explain This. Prefer adapting existing payloads into `BulwarkEvent` — never surface bare OS codes like `EPERM` alone (`explainOsError`). Phase 1 dry-run/restore is deferred (see `ROADMAP.md`).
