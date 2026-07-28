# Play Console release — Bulwark Android TV

This documents **CI signing secrets** and **Play Console upload** for
`com.bulwark.tv`. No keystores or service-account JSON belong in git.

Workflow: [`.github/workflows/android-tv-release.yml`](../../../.github/workflows/android-tv-release.yml)

## GitHub Actions secrets (add these yourself)

Repo secrets page (replace `OWNER/REPO` if needed):

https://github.com/kdairatchi/bulwark/settings/secrets/actions

| Secret | How to get it |
|--------|----------------|
| `BULWARK_TV_KEYSTORE_BASE64` | `./apps/android-tv/scripts/encode-keystore.sh path/to/upload.jks` |
| `BULWARK_TV_STORE_PASSWORD` | Upload keystore password |
| `BULWARK_TV_KEY_ALIAS` | Key alias (e.g. `bulwark-tv`) |
| `BULWARK_TV_KEY_PASSWORD` | Key password |
| `BULWARK_TV_PLAY_SERVICE_ACCOUNT_JSON` | Play API service-account JSON (plain text) |

## One-time Play Console / Cloud links

1. [Play Console](https://play.google.com/console) — create app package `com.bulwark.tv`
2. [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756) — enroll; keep your **upload** key for CI
3. [Google Cloud Console](https://console.cloud.google.com/) — create a service account + JSON key
4. Enable [Google Play Android Developer API](https://console.cloud.google.com/apis/library/androidpublisher.googleapis.com)
5. Play Console → **Users and permissions** — invite the service account (Internal testing release access)
6. Run workflow: https://github.com/kdairatchi/bulwark/actions/workflows/android-tv-release.yml

Encode helper + full checklist: this file + `../scripts/encode-keystore.sh`.


## How to ship

### Manual (recommended first run)

Actions → **Android TV Release** → **Run workflow**:

- Set `version_name` / `version_code` (or leave blank for defaults)
- Track: `internal`
- Status: `draft` (safe — does not roll out to testers until you promote)
- Upload: enabled

### Tag-driven

```bash
git tag tv-v0.1.1
git push origin tv-v0.1.1
```

Builds a signed AAB/APK, uploads artifacts to the workflow run, then uploads the
AAB to the **internal** track as a **draft**. Version code is derived from the
semver (`major*100000 + minor*1000 + patch`) unless overridden.

## Local parity

Same env vars work locally (see `keystore.properties.example`):

```bash
export BULWARK_TV_STORE_FILE=/absolute/path/to/upload.jks
export BULWARK_TV_STORE_PASSWORD=…
export BULWARK_TV_KEY_ALIAS=bulwark-tv
export BULWARK_TV_KEY_PASSWORD=…
export BULWARK_TV_VERSION_NAME=0.1.1
export BULWARK_TV_VERSION_CODE=1001
cd apps/android-tv
./gradlew :app:bundleRelease :app:assembleRelease
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Workflow fails “Missing secret …” | Secret not set on this repo/fork |
| Unsigned / signingConfig missing | `BULWARK_TV_STORE_FILE` empty after decode step |
| Play API 403 | Service account not invited in Play Console, or API not enabled |
| Play API 404 package | App `com.bulwark.tv` not created yet, or wrong package |
| versionCode conflict | Bump `version_code` input / tag — Play rejects reuse |

## Out of scope

- Promoting drafts to production automatically
- Storing the Play **app signing** key in CI (Play App Signing holds it)
- Electron desktop signing (separate Azure / Apple secrets in `release.yml`)
