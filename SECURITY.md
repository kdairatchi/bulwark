# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older versions | No |

We recommend always running the latest version of Bulwark.

## Reporting a Vulnerability

If you discover a security vulnerability in Bulwark, **please do not open a public issue.**

Instead, report it privately via [GitHub Security Advisories](https://github.com/kdairatchi/bulwark/security/advisories/new).

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a fix as quickly as possible. You will be credited in the release notes unless you prefer otherwise.

## Scope

This policy covers the Bulwark desktop application and its source code. It does not cover third-party dependencies — please report those to the respective maintainers.

## Security Design

Bulwark is a device security agent that operates with elevated permissions. We take this responsibility seriously:

- **Local-first** — Scans and security checks run locally. Cloud features are opt-in and, when enabled, collect only minimum-necessary metadata (never file contents, passwords, or packet payloads). See [docs/privacy/README.md](docs/privacy/README.md).
- **Minimal network use** — Network access is used for update checks and the optional cloud features you explicitly enable.
- **Open source** — Every operation is auditable. We encourage security researchers to review our code.
- **VirusTotal scanned** — Every release binary is automatically submitted to VirusTotal and results are linked in the release notes.
- **Signed binaries** — Windows releases are code-signed.
