# Security grep catalogs

## `lolbins.json`

Offline **Living-off-the-Land** (LOLBAS / LOLScripts) and high-confidence **technique**
patterns (AMSI bypass, injection primitives, webshell markers, curl|bash, etc.).

Used by:

- Local malware scanner (`matchLolbinContent` on scripts / LNK)
- Remote `RUN_MALWARE_SCAN` / `kind=lolbins` (process cmdline grep)
- Remote `RUN_VULNERABILITY_SCAN` technique subset (static heuristics only)

### What this is not

- Not a live zero-day / CVE intelligence feed (see ROADMAP Phase 5 for OSV/NVD/KEV)
- Not a full disk YARA marathon (cloud YARA remains separate)
- Not packet capture or ETW

### Schema

`rules/schema/lolbins.schema.json` — validated by `npm run validate:rules`.
