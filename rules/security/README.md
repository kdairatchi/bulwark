# Security catalogs

## `lolbins.json` (v1.1+)

Offline **Living-off-the-Land** (LOLBAS / LOLScripts), **technique**, and **static
vuln_heuristic** patterns. Surfaces: process cmdline, scripts, LNK, registry Run
keys, scheduled tasks / cron.

Used by:

- Local malware scanner (`matchLolbinContent` on scripts / LNK; `scanPersistenceLolbins` in persistence phase)
- Remote `RUN_MALWARE_SCAN` / `kind=lolbins` (process + persistence grep)
- Remote `RUN_VULNERABILITY_SCAN` technique + vuln_heuristic subset

### Categories

| Category | Examples |
|----------|----------|
| `lolbin` | mshta, certutil, regsvr32, forfiles, msdt, wuauclt, mavinject |
| `lolscript` | PowerShell encoded/IEX, curl\|bash, osascript, python -c |
| `technique` | AMSI/ETW bypass, LSASS dump, WMI persist, schtasks /create, SSH -R |
| `vuln_heuristic` | Log4Shell JNDI, Shellshock, Follina/msdt, PrintNightmare markers |

## `kev.json` (v1.0+)

Curated offline **CISA KEV** subset for **basic CVE matching** (name/alias + optional
`vulnerableBelow` version gate). Wired into `RUN_VULNERABILITY_SCAN` via `kev-matcher`.

**Live sync:** `kev-feed` can download the full CISA KEV JSON, cache it under userData,
and merge with vendored entries (vendored keeps version gates / richer aliases). Enable
with `parameters.kevSync=true` (parent vuln scan does this by default).

**EPSS:** `epss-client` enriches CVE/KEV/OSV findings via FIRST.org when `parameters.epss=true`.

**OSV:** pass `parameters.osv=true` for bounded OSV.dev package queries (parent checkbox).

**NVD:** pass `parameters.nvd=true` for bounded NVD 2.0 CPE queries. The adapter
only sends exact CPEs for known product mappings, caps requests per scan, and
supports `NVD_API_KEY` for higher-rate deployments. Results are cached per CPE
under Electron user data and refreshed every six hours using bounded
`lastModStartDate`/`lastModEndDate` windows plus HTTP validators when available.
The mapping includes conservative aliases for common products such as Firefox,
Apache HTTP Server, VS Code, Acrobat, VLC, Edge, and Docker Desktop; generic
names are intentionally rejected rather than guessed.

Vendor and distro feed adapters should normalize their native ranges through
`vendor-advisories.ts`. It supports inclusive `introduced`/`fixedIn` bounds,
KEV-style `vulnerableBelow`, Debian/RPM/Alpine revisions, and returns `unknown`
when either side lacks enough version evidence.

### Coverage vs gaps

| Capability | Status |
|------------|--------|
| Offline KEV name/version match (curated) | **Landed** |
| Live CISA KEV sync + disk cache | **Landed** (`kevSync`) |
| EPSS enrichment | **Landed** (`epss`) |
| Bounded OSV queries (`osv=true`) | **Landed (optional)** |
| Bounded NVD 2.0 CPE matching | **Landed (opt-in)** |
| Full product/vendor normalization | Phase 5 in progress |
| Live zero-day intel feed | Out of scope |
| Full LOLBAS dump (~1000+ bins) | Seed catalog; expand iteratively |
| ETW / process-tree / kernel | Not started |

### Schema

- `rules/schema/lolbins.schema.json`
- `rules/schema/kev.schema.json`

Validated by `npm run validate:rules`.
