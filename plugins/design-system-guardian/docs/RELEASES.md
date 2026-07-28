# Release Evidence Contract

## v0.3.8 source coordinates

The current public source candidate is 0.3.8. Codex, Claude Code, Kimi Code, the Flutter package, and generic Agent Skills bindings must match guardian_core.release.RUNTIME_VERSION. OpenClaw reuses the compatible Codex/Claude bundle and Qwen Code uses the same two integrity-bound Agent Skills. Every surface resolves to one Guardian core and exactly build-with-design-system and audit-design-system.

This source candidate adds personal-local, per-task and per-Figma-file design-system selection:

    guardian selection status --run-id <run-id>
    guardian selection preview --run-id <run-id> --input <discovery.json>
    guardian selection apply --input <permission-bound-selection.json>

The user must explicitly mark every complete discovered library candidate **Use** or **Do not use**. At least one published library must be selected, every unselected library is forbidden, and a previous selection never carries to another task, client, project, run, duplicate, or Figma file.

The existing Figma connection must also provide complete one-to-one catalog read-back for every canonical token, component, and icon, including token content, component variants/properties, and Code Connect mappings. Guardian rejects missing, duplicate, excluded, or version-drifted catalog/read-back mismatches before personal state is created and records the local evidence as `unprotected_caller_carried`, never as protected production attestation or independently proven Figma provenance.

Version 0.3.8 preserves every v0.3.2-v0.3.7 manifest, schema, authorization, channel event, score, history record, and exactly-two-skill contract. The externally signed enterprise onboarding and catalog route remains optional and unchanged. Personal selection evidence remains local and is not release authority, protected production authority, public Elo evidence, or telemetry.

A host reporting update_required, reload_required, or invalid has not loaded v0.3.8. reload_required with host_restart_required means the prior intact installation was restored; restart the exact watching host, rerun the same verified update, start a new task or session, and require version 0.3.8 plus two-skill read-back.

## v0.3.7 source coordinates

The v0.3.7 public source candidate used the same Codex, Claude Code, Kimi Code, Flutter, OpenClaw, Qwen Code, and generic Agent Skills distribution model with exactly build-with-design-system and audit-design-system.

This source candidate adds complete subjective judgment assessment plus selected exact-run conflict exceptions. Guardian explains every finding first, preserves raw findings, derives an effective result separately, accepts an optional reason, and supports append-only revocation through these exact portable forms:

    guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>
    guardian judgment apply --input <granted-bundle.json>
    guardian judgment status --profile <profile-id> --run-id <run-id>
    guardian judgment revoke --input <granted-revocation.json>

An exception never transfers to a duplicate file, new screen or flow, later run, or future version. It never overrides design-system compliance, Usage Rules, sentinels, stale/incomplete evidence, unsupported or not-assessed coverage, or protected production authority.

Version 0.3.7 preserves every v0.3.2-v0.3.6 manifest, schema, authorization, channel event, score, history record, and exactly-two-skill contract. The inherited v0.3.6 guardian rules list, permission-bound evaluator-v2 flow, and separate Usage Rules lane remain available. Public Elo v7 cases are synthetic. Assessments, reasons, decisions, revocations, company evidence, local Elo scores, benchmark results, and append-only history stay local and never enter Git, Elo, or telemetry.

A host reporting update_required, reload_required, or invalid has not loaded v0.3.7. reload_required with host_restart_required means the prior intact installation was restored; restart the exact watching host, rerun the same verified update, start a new task or session, and require version 0.3.7 plus two-skill read-back. This installation state is not release authority, and portable packaging does not prove automatic routing or an untested host runtime.

A public release must come from a clean authenticated public lineage. For v0.3.8, if a development branch contains internal planning artifacts or private local-path evidence, publish from the canonical public v0.3.7 lineage and replay only approved public source changes; do not rewrite that development history in place. The current public docs and manifests contain no absolute local path.

## Signed action manifest

`schemas/release/release-manifest.schema.json` describes both normal releases and restorations. Canonical signing bytes are:

```text
canonical-json({
  "domain": "design-system-guardian.release-manifest.v1",
  "manifest": <complete manifest with authority.signature removed>
})
```

Canonical JSON is UTF-8, sorted by key, compact, and rejects non-standard numeric values and duplicate keys. The `authority` object retains `schemaVersion`, `algorithm`, and `keyId` inside the signed payload. Only `signature` is removed.

The detached signature is canonical base64 for one 64-byte Ed25519 signature. The key ID is SHA-256 of the public SubjectPublicKeyInfo DER bytes.

## Manifest semantics

- `manifestType=release` requires `targetManifestDigest=null` and `reason=null`.
- `manifestType=restoration` requires an archived target digest and a canonical non-empty reason.
- `channelSequence` advances exactly one per channel.
- `sourceCommit` is one full lowercase 40- or 64-character Git object ID.
- `artifactDigest` is SHA-256 of the exact package bytes supplied for promotion.
- `stateSchemaVersion` must be supported by the running Guardian.
- `runtimeCompatibility` is the signed compatibility range for Guardian's deterministic runtime. It is not a claim that an untested Codex build was validated.

Stable manifests cannot use prerelease SemVer. Normal promotion must exceed every SemVer previously promoted on its channel; build metadata alone does not create a greater version.

## Local derived projection

The deterministic local ledger layer uses this layout outside Codex's replaceable plugin cache:

```text
~/.design-system-guardian/
  trust/release-authority-v1/
    public-key.pem
    binding.json
  releases/
    artifacts/<artifact-sha256>.plugin
    manifests/<manifest-sha256>.json
    history/canary/<sequence>-<event-id>.json
    history/stable/<sequence>-<event-id>.json
    channels/canary.json
    channels/stable.json
```

Manifests, artifacts, and history are create-once local projections. Channel files are derived pointers sealed by the host authority and checked against the retained history and archived signed actions. `recordedAt` is trusted event-attempt time; channel state separately records `eventRecordedAt` and `activatedAt`, with issuance, monotonicity, and current-clock bounds.

These account-owned files are not an external monotonic head. Coordinated deletion of a later local history event and its archived action can replay an older sealed prefix. Production therefore requires the fixed `CanonicalReleaseHeadProvider` contract in `guardian_core/release_head_provider.py`:

- authenticated latest-head reads from independently preserved/WORM storage;
- a monotonic compare-and-swap from the exact previous checkpoint;
- checkpoint lookup by digest for stable-to-canary evidence;
- no caller-selected path, JSON, environment override, local filesystem store, or in-memory production implementation.

This private pilot deliberately supplies only the protocol and an unconditional compile-time blocker—no provider resolver or production implementation. The four public channel functions always fail closed before reading local state. Configuration alone cannot unblock them; a future reviewed Guardian code release must integrate the fixed adapter and use its latest-head/checkpoint/CAS operations. The underscore-prefixed home-injected functions are deterministic local-ledger test seams, not production authority.

## Authority separation

The private release key is external. Production `guardian_core/release.py` loads public-key and signature-verification primitives only. Test-only signing helpers live under `tests/` and are not release tooling.

The public key is pinned once, must differ from the catalog approval key, and is bound to the immutable policy with host-sealed evidence. No normal migration, plugin reinstall, cachebuster, canary action, stable action, or rollback may replace it.

## Actual promotion status

Repository files, local ledger files, and version metadata are not channel authority. Until a future reviewed Guardian code release integrates the fixed external/WORM head provider and a release is externally signed and promoted, the correct answer is "not promoted."
