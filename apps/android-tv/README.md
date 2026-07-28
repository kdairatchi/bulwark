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

- JDK 17+
- Android SDK 34 (`ANDROID_HOME` / `local.properties` `sdk.dir`)
- Control plane: from the repo root, `npm run cloud:dev` (port 8787)

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

## Security model

Matches `docs/api/device-and-dashboard-api.md` and
`docs/threat-model/README.md#remote-command-model`:

- No shared API key — device generates Ed25519 at enroll
- Commands must pass allowlist + server signature + expiry + nonce checks
- No arbitrary shell / remote-exec command types

## Not in this slice (later Phase 4)

`VpnService` DNS blocking · APK cert/hash deep collection · emergency isolation ·
remote policy sync · Play distribution / signing pipeline.
