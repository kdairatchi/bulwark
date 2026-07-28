# Threat Model — Bulwrk

Bulwrk runs with **elevated permissions** and (optionally) manages devices
remotely, so it is itself a high-value target. This document captures the trust
boundaries, the biggest risks, and the required controls.

## Assets to protect

- Endpoints running the agent (integrity of scans, remediation, updates).
- The signed update channel (a compromised updater compromises every customer).
- The remote-command path (a hijacked command channel = fleet-wide RCE risk).
- User data (findings, device metadata) and cloud credentials / device keys.

## Trust boundaries (desktop)

```
Renderer  (untrusted content)  → Preload (allowlisted API) → Main (orchestration) → Privileged service (minimal signed commands) → OS
```

Required controls (Electron):

- `contextIsolation: true`, `nodeIntegration: false`, sandbox the renderer where supported.
- **Preserve the production strict CSP.** Dev strips CSP for HMR
  (`electron.vite.config.ts`); any future relaxation of the production CSP must be
  reviewed carefully.
- Strict IPC schemas; no shell-command concatenation; canonicalize all paths.

## Remote command model

Commands are signed, allowlisted, single-use, and expiring:

```json
{ "command_id": "cmd_123", "device_id": "dev_456", "type": "RUN_VULNERABILITY_SCAN",
  "parameters": {}, "issued_at": "...", "expires_at": "...", "nonce": "...", "signature": "..." }
```

Device verifies: server signature, tenant, device ID, **allowlist membership**,
timestamp, expiry, nonce/replay status, and local authorization policy. Every
command emits an append-only audit event.

**Allowed (v1):** inventory refresh, malware scan, vulnerability scan, health
assessment, update threat feeds, download approved app updates, quarantine a
*confirmed* file, block a domain, restart the agent.

**Not allowed (v1):** arbitrary shell/PowerShell, remote desktop, file browsing,
screen capture, credential retrieval, silent execution.

## Remediation safety

Three modes — **Observe → Recommend → Enforce**. Every enforced remediation requires:
precondition check, rollback/restore method, command allowlist, package-signature
validation, timeout, post-action verification, immutable log, and a user-visible
explanation. Never silently delete registry entries or system files from heuristics
alone.

## Risk scoring

Do not rank by CVSS alone:

```
Risk = severity × exploit_probability × known_exploitation × internet_exposure
       × application_activity × privilege_level × asset_importance × fix_availability
```

Application safety uses deterministic weighted signals (e.g. +25 unsigned executable,
+25 matched malicious network indicator, +20 persistence, −20 trusted signature,
−15 installed via trusted package manager). Display **evidence and confidence more
prominently than any number**. An LLM may only explain — never decide.

## Update system

Signed release artifacts, offline signing identity, protected release workflow,
hash verification, rollback protection, phased rollout, emergency revocation, and
(eventually) two-person release approval.

## Software supply chain (CI/CD gates)

Lint, type-check, unit/integration/IPC tests, cleaner-rule validation, Android
instrumentation tests, dependency review, CodeQL, secret scanning, license scanning,
SBOM generation, artifact signing, malware scan of release artifacts, installer smoke
tests, provenance attestation.
