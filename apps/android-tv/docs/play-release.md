# Play Console release — Bulwark Android TV

This documents **CI signing secrets** and **Play Console upload** for
`com.bulwark.tv`. No keystores or service-account JSON belong in git.

Workflow: [`.github/workflows/android-tv-release.yml`](../../../.github/workflows/android-tv-release.yml)

## Secrets to create (GitHub Actions)

Repo → **Settings → Secrets and variables → Actions → New repository secret**:

| Secret | Contents |
|--------|----------|
| `BULWARK_TV_KEYSTORE_BASE64` | Base64 of the **upload** keystore file (`.jks` / `.keystore`) |
| `BULWARK_TV_STORE_PASSWORD` | Keystore password |
| `BULWARK_TV_KEY_ALIAS` | Key alias |
| `BULWARK_TV_KEY_PASSWORD` | Key password |
| `BULWARK_TV_PLAY_SERVICE_ACCOUNT_JSON` | Full Play Developer API service-account JSON (plain text, not base64) |

Encode a keystore locally (never commit the raw file):

```bash
# from anywhere you keep the upload key
base64 -w0 path/to/bulwark-tv-upload.jks | pbcopy   # macOS
base64 -w0 path/to/bulwark-tv-upload.jks            # Linux → paste into the secret
```

Or use the helper:

```bash
./apps/android-tv/scripts/encode-keystore.sh path/to/bulwark-tv-upload.jks
```

## One-time Play Console setup

1. Create the app in [Google Play Console](https://play.google.com/console) with
   package name **`com.bulwark.tv`** (Android TV / Leanback).
2. Enroll in **Play App Signing** (Google holds the app signing key; you keep the
   **upload** key used by CI).
3. Create a Google Cloud **service account** with Play Console access:
   - Play Console → Users and permissions → Invite user → service account email
   - Grant **Release to testing tracks** (at least Internal testing)
4. In Google Cloud, enable **Google Play Android Developer API** and create a
   JSON key for that service account → paste into
   `BULWARK_TV_PLAY_SERVICE_ACCOUNT_JSON`.
5. Complete Play Console store listing / TV questionnaire enough that the
   Internal testing track accepts AABs (first upload may need a manual draft
   created in the console).

> Brand / signing identity: do not lock a public Play listing until the product
> brand is trademark-cleared (see `ROADMAP.md` Phase 0). Internal testing is fine
> earlier.

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
