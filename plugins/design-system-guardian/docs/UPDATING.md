# Updating and Releases

Guardian evolves in three separate layers:

| Layer | Update rule |
|---|---|
| Immutable policy | A normal update must preserve its exact digest. It is never weakened or replaced. |
| Selected catalog | Personal selection creates one exact task/file-bound local snapshot; optional enterprise approval retains its signed immutable snapshot under one profile. Profiles never blend. |
| Plugin logic | Reviewed SemVer release, deterministic one-version migration, canary verification, then stable promotion. |

## 0.3.8 release boundary

Version 0.3.8 preserves every v0.3.2-v0.3.7 capability and adds an additive personal-local selection route. At the beginning of every Guardian task and whenever the target Figma file changes, the agent must ask the user to mark every completely discovered published library candidate **Use** or **Do not use**.

The portable forms are:

    guardian selection status --run-id <run-id>
    guardian selection preview --run-id <run-id> --input <discovery.json>
    guardian selection apply --input <permission-bound-selection.json>

Status and preview are zero-write. Apply accepts only the exact confirmed project, run, target Figma file identity/version, complete library-decision set, catalog, and adapter binding. At least one library must be selected; every unselected library is forbidden. No selection transfers to a new task, client, project, run, duplicate, or Figma file.

The personal route is additive local evidence, not a migration and not protected production authority. It does not rewrite a v1 enterprise profile, externally signed snapshot, catalog authority, rule activation, evaluator permission, judgment history, release state, or old run pin. The optional signed enterprise onboarding remains available and unchanged.

Personal selections, target and library file identities, names, catalogs, profiles, snapshots, and run evidence stay local and never enter Git, public Elo fixtures, telemetry, or the release artifact. Codex, Claude Code, Kimi Code, Flutter, and generic Agent Skills versions are 0.3.8; OpenClaw and Qwen Code reuse the same package and exactly two skills.

## 0.3.7 release boundary

Version 0.3.7 preserves every v0.3.2-v0.3.6 capability and adds a local subjective-judgment sidecar over a sealed exact run. Guardian explains every finding first, preserves raw findings, and derives a separate effective result. The user may approve only selected conflicts for that exact version and run, with an optional reason, or fix the issue and evaluate again.

The portable forms are:

    guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>
    guardian judgment apply --input <granted-bundle.json>
    guardian judgment status --profile <profile-id> --run-id <run-id>
    guardian judgment revoke --input <granted-revocation.json>

Preview and status are zero-write. Apply and revoke require explicit permission for their exact digest-bound local operation. Revocation appends history. Every new screen or flow is assessed again; no decision is reusable across a duplicate file, later run, future version, or changed source evidence.

An exception can change only the effective judgment result for selected conflicts. It never overrides raw evidence, design-system compliance, Usage Rules, sentinels, stale/incomplete evidence, unsupported or not-assessed coverage, or protected production authority. Assessments, reasons, decisions, revocations, company evidence, and local Elo results remain local and never enter Git, Elo, or telemetry. Public Elo v7 inputs are synthetic only.

The Codex, Claude Code, Kimi Code, Flutter package, and generic binding versions are 0.3.7. OpenClaw and Qwen Code reuse the same reviewed bundle and two standard skills. Each host still requires its documented restart or reload and exact version/two-skill read-back; packaging does not claim automatic routing or an untested runtime.

## 0.3.6 release boundary

Version 0.3.6 preserves every v0.3.2-v0.3.5 capability and adds one separately permissioned evaluator-v2 sidecar. Installation alone does not expand v0.3.5 evaluator authority. `guardian rules upgrade preview --profile <id>` performs no writes; apply accepts only the exact permission-bound candidate and writes append-only local authorization evidence without changing rule snapshots or old permissions. Permission enables evaluator semantics and never approves rules or assets.

`guardian rules list --profile <id>` is zero-write in every outcome. It reports the exact rule snapshot, source state, evaluator, rule IDs/classes, capability statuses, fixed reasons, and active/not-assessed/informative counts without printing rule prose, company paths, design content, or user data.

After explicit evaluator-v2 permission, Guardian supports all six existing machine predicates, analyzer-proven `compilation_unit` and `widget_class` scope where defined, and child, descendant, and sibling relations. Judgment rules remain `not_assessed`; informative rules remain non-gating. New audit evidence carries a separate Usage Rules lane and retains the inherited design-system projection. Missing permission, incomplete analysis, disagreement, or source/integrity blockers never produce green.

Generic Agent Skills status is zero-write and returns `current`, `update_required`, `reload_required`, or `invalid`. A Windows watched-root promotion failure restores the prior intact install and returns `reload_required` with `host_restart_required`; close or restart the named host, rerun the same verified update, start a new task or session, and read back version `0.3.6` plus exactly two skills before claiming completion.

All company profiles, catalogs, usage rules, evaluator permissions, run evidence, local Elo scores/results/history, and user content remain local. The public v6 Elo suite contains only synthetic evidence. No v0.3.2-v0.3.5 schema, release entry, permission, score record, or history is rewritten.

## 0.3.5 release boundary

Version 0.3.5 preserves every v0.3.2-v0.3.4 capability and adds only permission-bound Safe Activation. `guardian rules activate preview` performs no writes. `guardian rules activate apply` accepts only the exact digest-bound permission bundle for a complete catalog v2 already signed by the selected profile's pinned external catalog authority. Permission enables the evaluator; it does not approve rules.

Apply writes a new immutable rule snapshot and approval-sequence continuation under the parallel `rule-snapshots/`, `rule-approval-sequences/`, and `current-rule-snapshot.json` namespace. It never mutates `profile.json`, v1 `snapshots/`, v1 `approval-sequences/`, `current-snapshot.json`, run pins, or v1 Flutter config. The first v2 sequence advances exactly one from the retained v1 high-water. Once v2 evidence exists, an invalid or unavailable v2 head blocks; there is no automatic v1 fallback.

Only `forbidden_identity_in_scope` + `compilation_unit` and `max_instances_per_scope` + `compilation_unit` are active in this release. Every other valid rule remains preserved and previewable but `not_assessed` until v0.3.6. Normal generic-host installation rejects a lower SemVer before modifying either installed skill. Restoration remains a separately authorized release action.

All company profiles, catalogs, usage rules, activation bundles, run evidence, and user content remain local. Public source and weighted Elo cases are synthetic and contain no company data.

## 0.3.4 release boundary

Version 0.3.4 preserves permission-bound setup, exact Figma read-back, approved duplicate-file lineage, built-in screen/final-flow UX evaluation, three separate result lanes, and portable two-skill packaging with host-controlled routing. It adds `guardian rules validate` as the preview-only Usage Rules Lane foundation for explicit Figma description markers and local rule artifacts.

Rule validation writes no Guardian or project state, remains outside audit and finalization, and cannot authorize production. Missing identity coverage stays `not_assessed`; every preview reports `localChangesPerformed=false` and `productionReady=false`. The immutable policy digest and exactly two visible skills are unchanged, and version 0.3.4 requires no state migration.

Every public update starts from a clean source checkout. Company profiles, design-system catalogs, setup candidates, generated Figma configs/observations, run evidence, prompts, product source, credentials, user activity, and local Elo history remain under `~/.design-system-guardian/` or another private input location and must not enter the commit, artifact, or Git history.

The public source update does not create automatic routing or protected production authority. Clean schema-v2 `personal_local` Figma or Flutter coverage and caller-carried UX evidence remain `not_assessed` until a reviewed protected host or CI attests them; every unprotected result keeps `productionReady=false`.

## Local development refresh is not a release

Codex may require a build-metadata cachebuster to reload an edited local plugin. Use the plugin-creator `update_plugin_cachebuster.py` helper and reinstall from the configured personal marketplace. That cachebuster is only a local pickup mechanism. It does not advance SemVer precedence, sign an artifact, create channel history, or authorize production. Claude Code, OpenClaw, Kimi Code, Qwen Code, and generic Agent Skills installations use their documented host refresh paths instead. See [Installing on Agent Hosts](INSTALLING.md#updating) for exact commands.

Keep the Codex, Claude Code, Kimi Code, Flutter package, and generated generic Agent Skills binding versions equal to `guardian_core.release.RUNTIME_VERSION`. For v0.3.8 they must all resolve to `0.3.8`. Start a new task or session after reinstall so skill discovery is refreshed. Validate that exactly `build-with-design-system` and `audit-design-system` appear under the host's normal namespace.

For a generic host, run `python <reviewed-package>/scripts/install_agent_skills.py --target-root <host-skill-root> --status` before and after replacement. `reload_required` with `host_restart_required` means the prior installation was restored but a host still watches the target. Close or restart that exact host, rerun the same verified update, reload or start a new session, and repeat the read-back. Do not report the candidate as installed while status is `update_required`, `reload_required`, or `invalid`.

## Mandatory clean-public-release check

After committing the candidate and before any push, run:

```powershell
python scripts/check_public_release.py --repository-root . --history
```

This local run inspects committed bytes and reachable history, compares the public tree with high-confidence identifiers and exact private-file hashes under `~/.design-system-guardian/`, including personal selection and target/library identity evidence, authenticates the prior canonical public Elo suite, and prints only redacted reason codes. A missing local Guardian directory is valid; bypassing the local comparison is not. CI independently runs structural and history validation with `--ci` because hosted runners do not possess account-local company data.

Any failure blocks publication. Never copy local company data into a release to diagnose the result.

If a development lineage contains internal planning artifacts or private local-path evidence, do not publish that lineage and do not rewrite it in place. Construct a clean candidate from the authenticated public v0.3.7 lineage, replay only approved public source changes, and rerun the committed-tree and reachable-history privacy gate before publication. Current public docs and manifests must contain no absolute local path.

## Release preparation

This section records the intended future production flow. Version 0.3.8 can prepare and externally sign evidence, but its public channel operation is an unconditional blocker and cannot complete step 8.

1. Review the entire change and select the next strict SemVer. Normal promotion must be greater than every normal version previously promoted in that channel, including versions followed by a restoration.
2. Run the complete unit/adversarial suite, plugin validator, skill validators, Python compilation, schema validation, and whitespace checks.
3. Validate installation in every host claimed by the release. A manifest or skill-validator pass does not substitute for a real runtime check; unavailable hosts remain explicitly unverified.
4. Build one immutable plugin artifact outside the replaceable cache and compute its SHA-256.
5. Record one full lowercase Git object ID: 40 characters for SHA-1 repositories or 64 for SHA-256 repositories. Abbreviated commits are forbidden.
6. Create a release manifest conforming to `schemas/release/release-manifest.schema.json`. The signed policy digest must remain `3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`.
7. Have the designated external release authority sign the exact bytes returned by `guardian_core.release.release_signing_payload`. Guardian does not sign and never receives the private key.
8. After a future reviewed release integrates the fixed provider, supply the signed manifest and exact artifact to `guardian_core.release.promote_release`; that implementation must authenticate latest head and complete monotonic CAS. In version 0.3.8 this call always blocks and accepts no configuration workaround.

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

A home created by version 0.2 has exactly five verified trust files and no Elo enrollment evidence. After installing version 0.3.3 or later, migrate that home once with:

```powershell
guardian elo migrate
```

This explicit command preserves the policy and catalog authorities byte-for-byte and creates a sealed score-1 enrollment receipt, marker, and genesis head. It refuses partial trust, unknown trust files, any existing ledger directory, or evidence of prior Elo enrollment while that local evidence remains.

Total local erasure is indistinguishable from a genuine 0.2 five-file layout because version 0.2 created no Elo anchor. Therefore this command cannot prove continuity with a deleted ledger: it establishes a new local ledger and reports its `ledgerId` with `newLedger=true` and `continuityReset=true`. Invoke it only for a genuine pre-Elo home. An immediate repeat while the sealed enrollment remains is a verified no-op for the same `ledgerId`: `changed=false`, while the stable origin disclosure remains `newLedger=true`, `continuityReset=true`, and `continuityFromPriorLedgerProven=false`.

Profile-artifact schema migrations are deterministic, idempotent, and exactly one schema version at a time. Elo enrollment is separate: fresh installs use a random `ledgerId`, while explicit legacy migration derives a stable ID from the preserved five-file trust evidence so strict partial writes can recover without guessing or replacing conflicting bytes. Its continuity reset is disclosed. Before profile-artifact replacement, Guardian preserves a digest-verified canonical backup. Interrupted work fails closed and can recover only from matching evidence. Future schemas are refused.

Version 0.3.8 does not migrate existing enterprise profiles, signed snapshots, catalog authorities, rules, judgments, or run pins. Personal selection starts in a separate local namespace and every new task/file creates fresh run-bound evidence. An existing enterprise home remains enterprise-authorized unless the user explicitly performs the personal-local selection flow; no old state is reinterpreted silently.

Archived releases are verified with their historical supported schema parser and signed compatibility metadata. New activation requires the current release and state schema versions; updating the runtime must retain old verifiers for every still-supported archived version.

Never edit migration history or a backup in place. Restoration creates a new append-only record; it does not remove the migration that occurred.

## Rollback

The following procedure is also reserved for a future reviewed release with the fixed provider integrated; version 0.3.8 always blocks the public rollback call.

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
