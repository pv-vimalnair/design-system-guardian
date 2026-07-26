# Security Policy

## Trust boundary

Design System Guardian treats agent instructions and plugin files as replaceable. The immutable policy, authority bindings, profiles, catalog snapshots, sealed evidence, migration history, and release archive live under the canonical account-owned `~/.design-system-guardian/` root.

The hard design-system rule cannot be weakened by a normal plugin update. If platform-level safety instructions conflict with it, the affected task stops; the conflict never authorizes an outside-system identity.

## Authorities

Guardian uses distinct authorities for distinct purposes:

- A host-owned HMAC authority seals snapshots, run evidence, bindings, and local ledger projections.
- The pinned catalog Ed25519 public key verifies external catalog approvals.
- The pinned release Ed25519 public key verifies external release and restoration manifests.
- A fixed external/WORM release-head provider supplies authenticated latest-head reads and monotonic compare-and-swap.

The release authority is create-once. Its private key must remain in an independently controlled signing system. Never place it in this repository, the plugin directory, Codex configuration, a company profile, CI logs, or `~/.design-system-guardian/`. Production Guardian code verifies only and deliberately exposes no signing command.

Replacing a designated authority is not a normal update or migration. It requires a separately reviewed trust-recovery procedure and must never be inferred from a key mismatch.

Catalog approval and release authority roles must use distinct Ed25519 keys.

## Catalog high-water integrity

Every catalog load, historical run-pin load, and ingestion enumerates and verifies the complete locally retained pair of immutable snapshots and sealed approval-sequence records. The two histories must have exactly the same approval sequences and exact pointer fields, and retained sequences must be contiguous from the first locally observed approval through the high-water. The sealed current pointer must equal the highest retained valid approval; an existing lower pointer is a replay and fails closed. A missing pointer is recovered only when both retained histories align exactly.

This local check detects deletion or truncation of either side while its counterpart remains, including deletion of the newest sequence record while the newer immutable snapshot is retained. It does not claim rollback resistance against coordinated deletion of both the newest immutable snapshot and its matching sequence record followed by replay of an older sealed pointer. Account-owned files are not WORM storage, and version 0.3.3 deliberately does not add an external catalog-head service. Deployments that must resist that coordinated deletion require an independently preserved monotonic/WORM catalog approval head in a future reviewed release.

## Release integrity

A release action fails closed unless all of these are exact:

- Ed25519 signature and pinned key ID
- immutable policy digest
- strict SemVer
- full 40- or 64-character Git object ID
- archived artifact SHA-256
- supported release and state schema versions
- signed Guardian runtime compatibility range
- contiguous channel sequence
- canary evidence before stable promotion
- exact sealed canary-event evidence retained by stable state and history
- a canonical external latest-head checkpoint before any trusted channel read or action

Normal downgrades, same-version replacements, unsigned manifests, wrong-key signatures, future schemas, and replacement artifacts are rejected. A rollback is a new signed restoration record referencing one archived release; it never deletes or rewrites prior evidence.

## Public-source privacy gate

Every public update must pass `python scripts/check_public_release.py --repository-root . --history` from a clean committed tree before push. The checker reads committed Git objects, rejects unapproved paths and object modes, runtime-state shapes, absolute account homes, high-confidence secret material, and matches against local Guardian file digests and high-confidence design-system identifiers. Its output contains reason codes only; it never prints private values or local paths.

CI repeats committed-tree and reachable-history checks with `--ci`. CI cannot inspect account-local Guardian data, so the local-data-aware pre-push run remains mandatory. The gate also authenticates the prior canonical public Elo suite and permits only additive benchmark evolution; absence is accepted only for the exact authenticated 0.2.0 bootstrap commit.

## Filesystem integrity

Guardian rejects redirected trust and state paths, non-canonical JSON, duplicate JSON keys, invalid seals, replayed channel pointers while the complete local archive is retained, broken history chains, non-monotonic or future timestamps, and attempts to rewrite local append-only projections. Generic-host runtime storage additionally rejects symlinks, Windows junctions, and all reparse-point redirects, and the production default is anchored under the real account-local `~/.design-system-guardian/runtimes/` path. A stale transaction lock blocks rather than being guessed safe to remove.

Local account-owned files are not WORM storage and cannot detect coordinated deletion of a sealed tail plus its archived manifest. They are never production channel authority. Trusted reads and actions require one fixed host adapter backed by independently preserved/WORM storage, authenticated latest-head semantics, and monotonic compare-and-swap. Arbitrary paths, environment-selected providers, caller-supplied JSON, and in-process/local substitutes are forbidden.

The public source release ships the provider protocol but no resolver or production implementation. Production channel reads, promotions, and restorations fail closed unconditionally. Configuration alone cannot unblock them; a future reviewed Guardian code release must integrate the fixed host adapter and its authenticated latest-head/CAS checks.

## Reporting a vulnerability

Do not include company catalogs, private profiles, credentials, unpublished Figma data, or authority material in a public report. Preserve the exact error, affected digest, and minimal reproduction, then send it through the private security channel designated by the plugin owner. No public security contact has been configured for this source release.

## Audit integrity

Catalog outcomes are re-resolved from the verified pinned snapshot at audit and finalization. Caller-declared statuses or selected identities are never authority.

For Flutter, `guardian audit` owns analyzer execution and never accepts caller-authored analyzer status. Backward-compatible version 1 requests remain readable; version 2 binds the selected adapter, project root, resolutions, final-flow UX evidence, and `adapterEvidence:null`. It binds the canonical project root, complete Dart source manifest, analyzer inputs and executable, shipped adapter bundle, run pin, generated config, sentinel expectations, and one diagnostic attestation per compilation unit. For Figma, version 2 requires the fixed Plugin API collector observation bound to the run config, exact file version, nodes, variables, text styles, components, variants/properties, and signed duplicate-file lineage. Finalization rejects changed, unbound, or replayed evidence.

Phase-local success is never labeled production readiness. Snapshot ingestion
reports `snapshotUsable`; preflight reports `pinCreated`. Only protected
finalization may emit `productionReady=true`.

Version 0.3.3 includes diagnostic Figma read-back and screen/final-flow UX evaluation. Proven violations or gaps can fail, but clean caller-carried Figma or UX evidence remains `not_assessed` until protected host attestation. These local mechanisms cannot issue `allowed` or prevent raw-tool bypass. Design-system compliance, UX/accessibility, and protected production authority stay separate, and `productionReady=false` without the protected lane.

## Supported source release

The current source declares version `0.3.3`. It is a public source release candidate until every claimed target host is validated and an externally authorized canary/stable release is completed. Source presence, unit tests, host-manifest validation, skill loading, or clean local Figma/UX evidence alone do not constitute a signed production release.
