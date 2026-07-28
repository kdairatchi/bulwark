# Bulwark Android TV Agent

Phase 4 of the Bulwark roadmap: a ten-foot Android TV agent that enrolls with the
device API (pairing code + per-device Ed25519 keys), reports installed-app
inventory / sideload findings, and polls for **server-signed, allowlisted**
remote commands.

## Modules

| Module | Role |
|--------|------|
| `:core` | Pure JVM library — crypto, command verify, HTTP client (no Android deps) |
| `:app` | Android TV (Leanback) UI + WorkManager poller + PackageManager inventory |

## Prerequisites

- JDK **21+** (Gradle `:core` / `:app` target JVM 21; CI uses Temurin 21)
- Android SDK 34 (`ANDROID_HOME` / `local.properties` `sdk.dir`)
- Control plane: from the repo root, `npm run cloud:dev` (port 8787)

Copy `local.properties.example` → `local.properties` and set `sdk.dir` if needed.

## JVM hello-world (no emulator required)

```bash
# terminal 1
npm run cloud:dev

# terminal 2
cd apps/android-tv
./gradlew :core:test :core:runAgentDemo
```

This enrolls a virtual “Living Room TV”, receives `RUN_MALWARE_SCAN`, verifies the
server signature, posts a result, and submits sample inventory + sideload findings.

## Build the TV APK

```bash
cd apps/android-tv
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Install on a device/emulator with the Leanback launcher. Emulator loopback to the
host control plane is `http://10.0.2.2:8787` (prefilled in the enroll UI).

### Release signing (local + CI)

Release builds stay **unsigned** unless you provide a keystore — so debug / unsigned
CI keeps working.

**Local**

1. Copy `keystore.properties.example` → `keystore.properties` (gitignored).
2. Point `storeFile` at a local `.jks` / `.keystore` (also gitignored).
3. Or set env vars: `BULWARK_TV_STORE_FILE`, `BULWARK_TV_STORE_PASSWORD`,
   `BULWARK_TV_KEY_ALIAS`, `BULWARK_TV_KEY_PASSWORD`.
4. Build: `./gradlew :app:bundleRelease :app:assembleRelease`

**CI / Play Console**

See [`docs/play-release.md`](docs/play-release.md) for the full secret list and
Play Console checklist. Workflows:

- `.github/workflows/android-tv-ci.yml` — `:core:test` on TV path changes (no secrets)
- `.github/workflows/android-tv-release.yml` — signed AAB/APK + optional Play upload
  (`workflow_dispatch` or tag `tv-v*`)

Required Actions secrets: `BULWARK_TV_KEYSTORE_BASE64`, `BULWARK_TV_STORE_PASSWORD`,
`BULWARK_TV_KEY_ALIAS`, `BULWARK_TV_KEY_PASSWORD`,
`BULWARK_TV_PLAY_SERVICE_ACCOUNT_JSON`.

```bash
./apps/android-tv/scripts/encode-keystore.sh path/to/upload.jks
```

Uploads default to the **internal** track as a **draft**. Bump `versionCode` via
workflow inputs, tag-derived semver, or `BULWARK_TV_VERSION_CODE`.

## Security model

Matches `docs/api/device-and-dashboard-api.md` and
`docs/threat-model/README.md#remote-command-model`:

- No shared API key — device generates Ed25519 at enroll
- Commands must pass allowlist + server signature + expiry + nonce checks
- No arbitrary shell / remote-exec command types

## VPN consent (honest enforcement)

- Isolate / `dnsGuardRequired` never reports `applied: true` until
  `VpnService.prepare()` is approved on the TV.
- TV shows a consent banner (and a post-enroll education card). Denial keeps
  **VPN PENDING** and offers **Retry Approve** — Bulwark never auto-launches the
  system dialog from WorkManager.
- Parent Cloud panel shows a **VPN PENDING** badge plus an on-device approve hint.
- Clearing isolation does **not** clear pending if `dnsGuardRequired` remains true.

## Not in this slice (later Phase 4)

Promoting Play drafts to production automatically · packet-level firewall beyond DNS.

## This slice also includes

- APK SHA-256 + signing-cert SHA-256 + permission risk in inventory
- Deeper static surface: debuggable, allowBackup, targetSdk, exported component counts
- Posture score / findings (`AppPosture`)
- Local DNS blocklist + `DnsGuardVpnService` (NXDOMAIN for blocked names)
- Remote **policy sync** and **emergency isolate** (allowlist DNS mode)
- **Event batching** (`POST …/network-events`) for DNS blocks / isolation / findings
- Commands: `BLOCK_DOMAIN`, `UPDATE_THREAT_FEEDS`, `ISOLATE_DEVICE`,
  `CLEAR_ISOLATION`, `APPLY_POLICY`, real `RUN_HEALTH_ASSESSMENT`
- Optional local release signing scaffold (`keystore.properties`)
- CI signed release + Play Console draft upload (`.github/workflows/android-tv-release.yml`)
