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
- Two cloud paths exist: legacy Pusher/API-key agent (`cloudAgent`, `BULWARK_CLOUD_URL`) and the new pairing/Ed25519 device API (`deviceCommandAgent`, `DEVICE_API_URL`, default `http://127.0.0.1:8787`). Run the reference control plane with `npm run cloud:dev` (separate Node process — not part of Electron). Demos: `scripts/device-client-demo.mjs`, `scripts/command-demo.mjs`, `scripts/device-agent-demo.mjs`. Do not put a bare `cloud/` entry in `.gitignore` (use `/cloud/` only) or `src/cloud/` will be ignored.
- Android TV agent lives in `apps/android-tv/` (see its README). JVM protocol tests/demo need JDK 17+ only: `cd apps/android-tv && ./gradlew :core:test :core:runAgentDemo` with `cloud:dev` running. APK builds need `ANDROID_HOME` / `local.properties` `sdk.dir`. Emulator → host control plane URL is `http://10.0.2.2:8787`.
