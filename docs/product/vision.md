# Product Vision — Bulwrk

> **Brand.** **Bulwrk** is the permanent product name.
> **Still open:** public marketing domain and support email — do not lock those
> until chosen. Cloud hosts stay env-configured; defaults are non-resolving
> placeholders.

## The pitch

**Protect every device in your home — without needing to be a cybersecurity expert.**

Bulwrk is a **family-focused device security platform** that protects Windows,
macOS, Linux, Android phones/tablets, Android TV boxes, and home networks from
malware, unsafe apps, vulnerable software, malicious traffic, and privacy risks.

It is deliberately **not** marketed as "another cleaner." The cleaning engine
(inherited from the upstream Kudu fork) is one capability of the desktop endpoint
agent — not the product.

## Why now

Compromised streaming devices and sideloaded Android TV apps are a real, growing
threat. The FBI has warned that compromised streaming devices and sideloaded
applications can contain backdoors, join residential proxy networks, and expose the
rest of a home network. Most households have no tooling to see or stop this.
Android TV protection is therefore our first **unique** feature.

## Product shape

A local security agent plus an optional cloud control plane:

```
Desktop Agent          Android Agent           Network Sensor          Cloud Control Plane
├── Windows            ├── Phones              ├── DNS filtering       ├── Device dashboard
├── macOS              ├── Tablets             ├── Malicious dest.     ├── Alerts
└── Linux              └── Android TV boxes        blocking            ├── Vulnerability intel
                                               ├── Device discovery    ├── Breach monitoring
                                               └── Traffic risk        ├── Reports
                                                   analysis            └── Remote actions
```


## Principles (non-negotiable)

- **Local-first.** Core protection works without the cloud.
- **Cloud is opt-in.** Cloud features require limited, minimum-necessary telemetry.
- **Transparent risk, not fake AI.** A deterministic, weighted risk engine produces
  the score and evidence; an LLM may only *explain* the result in plain language —
  it never decides whether software is malicious.
- **Metadata, not content.** Never collect file contents, passwords, private
  messages, full packet captures, or media streams. See
  [privacy architecture](../privacy/README.md).
- **Safe by construction.** Remote actions use a signed, allowlisted command set;
  remediation is Observe → Recommend → Enforce with rollback. See
  [threat model](../threat-model/README.md).

## Positioning & tiers (draft)

Free/Community (local agent, 1–3 devices) · Personal (~$5–8/mo, cloud dashboard,
breach monitoring) · Family (~$10–15/mo, Android TV protection, remote isolation) ·
Pro/Small Business (~$20–40/mo, patch policies, audit log, API) · Managed/MSP
(multi-tenant, white-label). SSO/SCIM/advanced retention are business-tier only.

Open-core: the desktop agent, cleaning engine, basic malware/vuln/health checks,
rules format, and CLI stay open source; the hosted control plane and continuous
threat intelligence are the paid service.

## MVP objective

> Show a user which devices and applications may be putting their home at risk, and
> help them fix the problems safely.

MVP scope and explicit non-goals live in [`ROADMAP.md`](../../ROADMAP.md).

## Naming, domain & email

**Product name:** Bulwrk (permanent).

**Still open:** public marketing domain and support email. Do not invent or ship a
locked `bulwrk.com` / `support@…` until those are chosen. Cloud control-plane hosts
remain env-configured (`BULWRK_CLOUD_URL` / `VITE_BULWRK_CLOUD_URL`) with
non-resolving placeholders by default.

**Package IDs already in use:** `com.bulwrk.app` (desktop), `com.bulwrk.tv`
(Android TV). Prefer keeping these stable. Store signing may proceed under those
IDs; public listing copy should say Bulwrk.

Optional hygiene before a public launch: USPTO / store / domain searches for
conflicts on the chosen *domain and email*, plus counsel review.
