# Security grep catalogs

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

### What this is not (still missing)

| Capability | Status |
|------------|--------|
| Live CVE / OSV / NVD matching | **Phase 5** — not this catalog |
| CISA KEV + EPSS enrichment | **Phase 5** |
| Live zero-day intel feed | **Out of scope** (static heuristics only) |
| Full LOLBAS project dump (~1000+ bins) | Seed catalog (~70 rules); expand iteratively |
| ETW / kernel / process-tree correlation | Not started |
| Full disk YARA marathon remotely | Local malware UI path only |
| Packet firewall | Deferred |

### Schema

`rules/schema/lolbins.schema.json` — validated by `npm run validate:rules`.
