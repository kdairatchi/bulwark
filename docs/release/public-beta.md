# Public beta validation

This is the Phase 6 evidence plan for the first public beta. It is a release
checklist, not a claim that the targets have already been measured.

Reports use the versioned `BetaReport` shape and can be checked with:

```sh
npm run validate:beta-report -- path/to/report.json
```

Start from [`beta-report.template.json`](beta-report.template.json), then replace
the placeholder build and device fields with the redacted test values.

## Scope

- Windows first, with macOS/Linux smoke coverage from the existing CI matrix.
- 20–50 desktop testers.
- At least five Android TV devices from at least two manufacturers.
- No production enrollment data in local fixtures or test reports.

## Validation matrix

| Area | Record | Release gate |
|---|---|---|
| False positives | reviewed findings / total findings, split by category | trend is understood; no unresolved high-severity false-positive cluster |
| Scan duration | median and p95 by OS and scan kind | p95 is documented for the tested hardware |
| Resource use | peak CPU, RSS, disk, and Android battery impact | no sustained runaway resource use; outliers have owners |
| DNS protection | legitimate-domain block reports and resolver failures | every blocked-legitimate report is reproducible and actionable |
| Remediation | attempted, succeeded, failed, reverted | destructive actions have an explainable failure or rollback path |
| Enrollment | attempted, successful, expired, retried | failures are categorized by pairing, network, or device state |
| Comprehension | tester can explain score, finding, and next action | usability issues are recorded with screenshots or repro steps |

## Required evidence per build

1. Commit SHA, platform, OS version, hardware model, and app version.
2. `npm test`, `npm run build`, rule validation result, and CLI smoke output.
3. Scan start/end timestamps and scan parameters; never include file contents or
   secrets in the report.
4. Finding counts before and after review, including category and confidence.
5. Enrollment and remediation outcomes with redacted error categories.
6. Open defects linked to an owner, severity, and planned disposition.

## Tester safety

- Use disposable or explicitly consented devices and a test dashboard account.
- Keep remote shell, packet decryption, and unattended destructive cleanup out of
  the beta scope.
- Require confirmation before quarantine, isolation, policy changes, or cleanup.
- Stop a test when DNS protection blocks a required recovery or update domain.

## Exit review

- [ ] Desktop and Android TV evidence collected for the target sample.
- [ ] False-positive and blocked-legitimate findings reviewed.
- [ ] No open release-blocking security or data-loss defect.
- [ ] Rollback and support instructions tested by someone other than the author.
- [ ] Release notes describe known limitations and telemetry retention.
