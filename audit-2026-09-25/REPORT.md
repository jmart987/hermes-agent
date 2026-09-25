# Hermes security audit completion report

Completed the eight-area static security audit of public Hermes Agent commit `28545254ddd02eaf01107a9ddf83b3ee9ae127f8`, exact tag `rc.11-v0.21.5`, on 2026-09-25.

**Overall verdict: FAIL for unrestricted use with untrusted inputs.** Principal gaps are the unknown/noninteractive command-approval fallback, private-network desktop link-title fetching, and unbounded image-save downloads. Additional concerns cover local dashboard trust, incomplete credential-store isolation, conditional API approval behavior, mutable updates, and dependency advisories. Full findings, remediation recommendations and pinned file:line evidence are in [AUDIT.md](AUDIT.md).

Deliverables:

- `AUDIT.md`: For-Julian summary first (11 lines), verdicts for all eight areas, direct evidence distinguished from inference, named CVE analysis, final completion marker.
- `egress-literals.tsv`, `egress-hosts.tsv`, `egress-scan.json`, `iana-tlds.txt`: 27,712 inclusive literal/candidate occurrences across 5,103 scoped text files; 4,332 host candidates. These are source inventories, not observed traffic or a complete dynamic egress allowlist.
- `DEPENDENCIES.md`, `dependency-components.json`, `osv-results.json`, `osv-details.json`: 2,800 registry package/version pairs checked (327 PyPI, 2,473 npm); 21 matched package/version pairs, 50 advisory identifiers before alias deduplication; no failed batches or unread result pages.
- Public CNA records and `PUBLIC-SOURCES.md`: primary advisory provenance; no exploit execution.
- Independent collection/summary/verification scripts and `verification.json`: reproducible evidence processing without importing Hermes.

Verification: exact source identity confirmed; all audited source remained unchanged; 166 distinct source citation locations validated; eight section verdicts and completion markers checked; scoped Git diff reviewed. No install, build, source tests, Hermes import, requests to a running Hermes service, package resolution, inspection of application credentials, or changes to the original installation were performed. Dependency matching is a public lockfile analysis, not an installed-runtime vulnerability test. Offline runtime behavior was not exercised.

Rework: the first dependency query included the editable project placeholder `hermes-agent==0.0.0`; its 20 advisory IDs were excluded, and the collector was fixed to require registry sources. Independent comparison confirmed all 327 registry Python tuples were queried and that placeholder was the only extra. The egress scan was expanded from a short suffix list to the saved IANA/reserved suffix list and general URI schemes. An intermediate scan was optimized to avoid repeated matching within long tokens; final inventory/document counts were reconciled. Original reporter prose is linked instead of included in the final artifact tree.

Repository safety: worked in isolated shared clones; source checkout and all commits occurred only in the owned isolated audit checkout. No checkout/reset/stash/clean/sparse-checkout/worktree-removal operation was performed in the live workspace or other live project. Audit-only changes are on `audit/security-20260925`; staged evidence and the complete draft were committed and pushed during the work. The completion commit uses exactly `HERMESAUDIT-DONE` as its message and publishes this report on that same audit branch. No existing public branch was overwritten or force-pushed.

Addenda applied: **none**. `ADDENDA.md` existed and was empty at start, between phases, after intermediate commits, and immediately before this report. No `USAGE-GUARD-CHECKPOINT` was present at phase checks.

Delegation: **none**. No child/replacement owner or unattended worker was launched. Short-lived audit evidence processes completed; no third-party application code ran.

The audit is complete; remediation is recommended but was outside this read-only assignment. Source review supports the findings, while dynamic exploitability and runtime/offline acceptance remain explicitly untested.

HERMESAUDIT-DONE
