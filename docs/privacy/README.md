# Privacy Architecture — Bulwrk

Our biggest competitor is not another cleaner — it is **user distrust**. The upstream
project promoted "no telemetry"; Bulwrk must be explicit that **cloud features
require limited telemetry** and that users can stay in **local-only mode**.

## Principles

- Local-first operation; cloud features are opt-in.
- Minimum-necessary collection; no selling personal data; no advertising SDKs.
- No packet-payload collection by default; clear retention controls; device deletion
  and account export; transparent rules; signed updates; verifiable builds where practical.

## Data classes

**Always local (never leaves the device):** file contents, browser contents,
passwords, documents, packet payloads, screenshots.

**Cloud-optional (only with opt-in):** device metadata, OS version, software
inventory, security findings, destination indicators, resource telemetry, scan
outcomes, command audit logs.

**Never collected:** passwords, authentication cookies, private messages, full packet
captures (by default), personal documents, media streams.

## Event shape (metadata, not content)

```json
{
  "device_id": "dev_123", "app_id": "com.example.player",
  "destination": "example.invalid", "destination_type": "domain",
  "port": 443, "protocol": "tcp", "decision": "blocked",
  "reason": "known_c2", "confidence": 0.97, "timestamp": "2026-07-27T18:30:00Z"
}
```

## Breach monitoring privacy

- Verify email ownership; store the email **encrypted at rest with a tenant-specific
  key** plus a lookup hash for deduplication; store only normalized breach references
  and review status. Notify only on *new* exposure.
- Use the breach provider (e.g. Have I Been Pwned) per its API authorization,
  rate-limit, attribution, and acceptable-use terms.
- Password exposure checks must use a **privacy-preserving range query** — never send
  the full password or full password hash.

## Current fork status

The desktop agent is local-first today. The cloud control-plane endpoint is **not**
part of this fork: `BULWRK_CLOUD_URL` defaults to a non-resolving placeholder and
cloud features stay dormant until a user opts in with an API key pointed at their own
control plane.
