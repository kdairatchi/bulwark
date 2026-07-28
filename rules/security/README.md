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

Optional live enrichment: pass `parameters.osv=true` to also query OSV.dev for a
small allowlisted set of packages (soft-fail, bounded).

### Coverage vs gaps

| Capability | Status |
|------------|--------|
| Offline KEV name/version match (curated) | **Landed** |
| Bounded OSV queries (`osv=true`) | **Landed (optional)** |
| Full CISA KEV catalog sync | Not yet (subset only) |
| NVD bulk / CPE matching | **Phase 5 incomplete** |
| EPSS enrichment | **Phase 5 incomplete** |
| Live zero-day intel feed | Out of scope |
| Full LOLBAS dump (~1000+ bins) | Seed catalog; expand iteratively |
| ETW / process-tree / kernel | Not started |

### Schema

- `rules/schema/lolbins.schema.json`
- `rules/schema/kev.schema.json`

Validated by `npm run validate:rules`.
