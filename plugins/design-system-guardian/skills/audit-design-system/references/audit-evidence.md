# Audit evidence checklist

Before accepting final audit evidence, verify:

- one explicit profile; no cross-profile identities
- immutable policy digest and pinned catalog-authority key verified
- one pinned snapshot and source-cut vector for the full audit
- exact source freshness at finalization time
- all eight categories present with assessed and total counts
- adapter binding matches profile, policy, snapshot, and source cut
- adapter config digest exactly matches Guardian's deterministic regeneration from the pinned signed snapshot
- raw values, framework defaults, unapproved variants, and suppressions are diagnostics
- each resolution is canonical, ordered, and bound to the run
- every `allowed` resolution selects the exact requested identity
- every `missing` result has an exact fixed sentinel; no other status has one
- resolution summaries, sentinel counts, diagnostics, UX checks, and coverage are derived from evidence
- design-system and UX/accessibility lanes remain separate
- inaccessible approved assets are design-system gaps, not substituted fixes
- `not_assessed`, `unsupported`, incomplete, stale, or unavailable evidence never becomes a pass

Readable reports are projections only. Treat the sealed canonical JSON and verified digests as authoritative.
