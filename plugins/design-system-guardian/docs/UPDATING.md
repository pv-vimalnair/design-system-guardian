# Updating and Releases

Guardian evolves in three separate layers:

| Layer | Update rule |
|---|---|
| Immutable policy | A normal update must preserve its exact digest. It is never weakened or replaced. |
| Company catalog | Each approved source change creates a new immutable snapshot under its one profile. Profiles never blend. |
| Plugin logic | Reviewed SemVer release, deterministic one-version migration, canary verification, then stable promotion. |

## Local development refresh is not a release

Codex may require a build-metadata cachebuster to reload an edited local plugin. Use the plugin-creator `update_plugin_cachebuster.py` helper and reinstall from the configured personal marketplace. That cachebuster is only a local pickup mechanism. It does not advance SemVer precedence, sign an artifact, create channel history, or authorize production. Claude Code, OpenClaw, Kimi Code, and generic Agent Skills installations use their documented host refresh paths instead.

Keep the Codex, Claude Code, and Kimi Code manifest versions equal to `guardian_core.release.RUNTIME_VERSION`. Start a new task or session after reinstall so skill discovery is refreshed. Validate that exactly `build-with-design-system` and `audit-design-system` appear under the host's normal namespace.

## Mandatory clean-public-release check

After committing the candidate and before any push, run:

```powershell
python scripts/check_public_release.py --repository-root . --history
```

This local run inspects committed bytes and reachable history, compares the public tree with high-confidence identifiers and exact private-file hashes under `~/.design-system-guardian/`, authenticates the prior canonical public Elo suite, and prints only redacted reason codes. A missing local Guardian directory is valid; bypassing the local comparison is not. CI independently runs structural and history validation with `--ci` because hosted runners do not possess account-local company data.

Any failure blocks publication. Never copy local company data into a release to diagnose the result.

## Release preparation

This section records the intended future production flow. Version 0.3.2 can prepare and externally sign evidence, but its public channel operation is an unconditional blocker and cannot complete step 8.

1. Review the entire change and select the next strict SemVer. Normal promotion must be greater than every normal version previously promoted in that channel, including versions followed by a restoration.
2. Run the complete unit/adversarial suite, plugin validator, skill validators, Python compilation, schema validation, and whitespace checks.
3. Validate installation in every host claimed by the release. A manifest or skill-validator pass does not substitute for a real runtime check; unavailable hosts remain explicitly unverified.
4. Build one immutable plugin artifact outside the replaceable cache and compute its SHA-256.
5. Record one full lowercase Git object ID: 40 characters for SHA-1 repositories or 64 for SHA-256 repositories. Abbreviated commits are forbidden.
6. Create a release manifest conforming to `schemas/release/release-manifest.schema.json`. The signed policy digest must remain `3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`.
7. Have the designated external release authority sign the exact bytes returned by `guardian_core.release.release_signing_payload`. Guardian does not sign and never receives the private key.
8. After a future reviewed release integrates the fixed provider, supply the signed manifest and exact artifact to `guardian_core.release.promote_release`; that implementation must authenticate latest head and complete monotonic CAS. In version 0.3.2 this call always blocks and accepts no configuration workaround.

The first production enrollment supplies only the external authority's public PEM to `enroll_release_authority`. Enrollment is create-once, and the release key must differ from the pinned catalog approval key. A different key is an integrity failure, not an automatic rotation.

## Canary and stable

Canary and stable have independent contiguous `channelSequence` values starting at 1.

After a future reviewed provider integration, promote to canary first. Exercise the installed package in a fresh session on every claimed host, run both skills, confirm deterministic evidence, and record any target-runtime limitation. Stable promotion then requires a separately signed stable manifest whose release coordinates exactly match a normal release already preserved in canary history:

- plugin version
- full source commit
- artifact digest
- immutable policy digest
- state schema version
- Guardian runtime compatibility range

A same-looking rebuilt artifact is not the same release.

Stable state and every stable history event retain the SHA-256 of the exact sealed canary promotion event. If that proof is unavailable, changed, or incomplete, stable verification fails rather than silently accepting equivalent coordinates.

## Migrations

A home created by version 0.2 has exactly five verified trust files and no Elo enrollment evidence. After installing version 0.3.2, migrate that home once with:

```powershell
guardian elo migrate
```

This explicit command preserves the policy and catalog authorities byte-for-byte and creates a sealed score-1 enrollment receipt, marker, and genesis head. It refuses partial trust, unknown trust files, any existing ledger directory, or evidence of prior Elo enrollment while that local evidence remains.

Total local erasure is indistinguishable from a genuine 0.2 five-file layout because version 0.2 created no Elo anchor. Therefore this command cannot prove continuity with a deleted ledger: it establishes a new local ledger and reports its `ledgerId` with `newLedger=true` and `continuityReset=true`. Invoke it only for a genuine pre-Elo home. An immediate repeat while the sealed enrollment remains is a verified no-op for the same `ledgerId`: `changed=false`, while the stable origin disclosure remains `newLedger=true`, `continuityReset=true`, and `continuityFromPriorLedgerProven=false`.

Profile-artifact schema migrations are deterministic, idempotent, and exactly one schema version at a time. Elo enrollment is separate: fresh installs use a random `ledgerId`, while explicit legacy migration derives a stable ID from the preserved five-file trust evidence so strict partial writes can recover without guessing or replacing conflicting bytes. Its continuity reset is disclosed. Before profile-artifact replacement, Guardian preserves a digest-verified canonical backup. Interrupted work fails closed and can recover only from matching evidence. Future schemas are refused.

Archived releases are verified with their historical supported schema parser and signed compatibility metadata. New activation requires the current release and state schema versions; updating the runtime must retain old verifiers for every still-supported archived version.

Never edit migration history or a backup in place. Restoration creates a new append-only record; it does not remove the migration that occurred.

## Rollback

The following procedure is also reserved for a future reviewed release with the fixed provider integrated; version 0.3.2 always blocks the public rollback call.

Rollback is an externally authorized release action, not a file copy or version decrement.

1. Select a normal release manifest that was previously promoted on the same channel and remains in the external archive.
2. Create a new `restoration` manifest with the channel's next sequence, the target's exact version/commit/artifact/policy/schema/compatibility coordinates, its manifest digest in `targetManifestDigest`, and a non-empty reason.
3. Have the designated external authority sign that new restoration manifest.
4. Apply it with `rollback_release`.

Guardian logs a new restoration event and points the channel to the preserved artifact. It never deletes, edits, or rewrites the intervening releases.

## Operator blockers

Stop instead of improvising when the external public authority is not enrolled, a signer is unavailable, the fixed external/WORM head provider is unavailable, a signature or sequence is missing, the artifact was rebuilt, the source commit is abbreviated, a claimed target-host validation is unavailable, or the policy digest differs. None of these states authorizes a local key, test signer, unsigned promotion, local/in-memory head substitute, or nearest substitute.

## Private-pilot blocker

`guardian_core/release_head_provider.py` currently provides the strict host-adapter protocol and an unconditional compile-time blocker; it has no resolver or production implementation. No actual trusted channel read, canary promotion, stable promotion, or restoration can be claimed until a future reviewed Guardian code release integrates one fixed host provider and invokes authenticated latest-head, checkpoint, and monotonic compare-and-swap operations on every channel path. Configuration alone cannot unblock this version. Test-only local-ledger exercises do not constitute promotion.
