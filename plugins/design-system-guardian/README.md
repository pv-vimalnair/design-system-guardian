# Design System Guardian

> Repository overview, installation, and product positioning: [root README](../../README.md).

Design System Guardian is one updatable Codex plugin with exactly two visible skills:

- `build-with-design-system` composes product UI with UX reasoning while enforcing exact approved identities.
- `audit-design-system` independently audits compliance and UX/accessibility without changing product files.

Everything else in this directory is shared plugin infrastructure. It is not another skill or plugin.

## The immutable rule

Only exact, explicitly approved identities from one selected company profile and one pinned, complete catalog snapshot may be selected. Similar names, nearest colors, equal-value literals, framework defaults, wrappers, substitutes, community assets, generated icons, manual recreation, rounding, and name-based guessing are not approval.

Only a proven `missing` result from a fresh, complete source may create a fixed diagnostic sentinel. A sentinel is conspicuous, remains outside the design system, and always sets `productionReady=false`. Unavailable, incomplete, stale, ambiguous, conflicting, invalid, unsupported, and not-assessed states never become `missing`.

Policy precedence is:

`immutable policy -> evolving validators -> selected company profile -> pinned catalog`

Deny always wins. The create-once policy digest is:

`3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`

## Trust and data boundaries

Replaceable plugin code contains validators, schemas, adapters, and skills. Private and append-only state lives outside the Codex plugin cache under the canonical account-owned root:

`~/.design-system-guardian/`

That root holds the immutable policy anchor, pinned public authorities, isolated company profiles, immutable snapshots, sealed run evidence, migration history, and archived releases. Production CLI entry points do not accept a redirected Guardian home.

The existing Figma connection is reused for discovery and refresh. Guardian does not add another Figma credential store or claim that Figma search alone proves approval.

## Portable CLI

The portable CLI implementation is `scripts/guardian.py`. A protected gate must use an authority-bound absolute interpreter or signed standalone executable. Private-pilot diagnostics may use a host-supplied absolute Python executable after recording its path and SHA-256, but those results can never confer production authority. The POSIX and Windows convenience wrappers deliberately exit `4` instead of discovering Python from `PATH`.

The command surface is:

- `doctor`
- `profile validate`
- `snapshot ingest`
- `preflight`
- `resolve`
- `adapter flutter config`
- `audit`
- `finalize`
- `migrate`

Exit codes are deterministic: `0` pass, `1` violations or sentinels, `2` policy/configuration/integrity failure, `3` unavailable/stale/incomplete source, and `4` unsupported adapter or incomplete coverage.

## Release and update model

Plugin source updates use reviewed SemVer and deterministic migrations. Release authority is separate from agent behavior:

- Guardian pins exactly one externally held Ed25519 release authority's public key.
- Production code verifies signatures only; it has no private-key generator, private-key import, or signing command.
- `canary` and `stable` have independent contiguous sequences.
- Stable promotion requires the exact version, full Git commit, artifact digest, policy digest, state schema, and compatibility range already present in canary history.
- A normal promotion must exceed every SemVer previously promoted on that channel. A downgrade is accepted only as a new externally signed restoration action that names an archived, previously promoted release.
- Signed manifests, package bytes, channel pointers, and append-only history are stored under `~/.design-system-guardian/releases/`, not in the replaceable cache.

A personal-marketplace or cachebuster installation is an unsigned development install; it does not create a canary or stable release. In 0.1.1 the provider is an unconditional compile-time stub: configuration cannot unblock it, and every public trusted channel read, promotion, and restoration fails closed. A future reviewed code release must integrate and invoke one fixed external/WORM provider's authenticated latest-head, checkpoint, and monotonic compare-and-swap operations before trusted releases can operate.


See [Trusted Execution](docs/TRUSTED_EXECUTION.md), [Updating and Releases](docs/UPDATING.md), and [Release Evidence Contract](docs/RELEASES.md). No real stable promotion is implied by the source version in `.codex-plugin/plugin.json`.

## Flutter pilot

Version 0.1 is Flutter-first. `guardian audit` owns analyzer execution: it derives a run-bound allowlist, hashes every relevant Dart source and analyzer input, analyzes an external staging copy, requires one config-bound attestation per compilation unit, scans suppression attempts, and seals the resulting evidence. Caller-authored analyzer results are not audit inputs.

The adapter uses Dart's supported analyzer-plugin structure and emits exact diagnostics for unapproved visual identities and suppression attempts. The selected profile must pin the full Dart SDK artifact for the current platform plus exact `flutter` and other package-config dependencies. Ambient `PATH` is discovery only: Guardian verifies and stages the bound SDK, runs it with a minimal environment, verifies and stages the complete Dart package-config closure, and rechecks both evidence sets during finalization. Local Git identity is read directly from bounded repository metadata; Guardian never executes a `git` binary selected from `PATH`.

The private pilot does not yet include a trusted UX/accessibility evaluator. UX checks supplied in an audit request are context only: Guardian canonicalizes that lane to `not_assessed`, exits `4`, and refuses a production pass. A future reviewed release must add host-attested UX evidence before exit `0` is possible.

## Repository map

- `.codex-plugin/plugin.json` — Codex plugin metadata accepted by the target validator.
- `skills/` — exactly the two visible skills.
- `guardian_core/` — deterministic policy, catalog, audit, migration, and release enforcement.
- `adapters/flutter/` — Flutter analyzer adapter and fixed sentinel widget.
- `schemas/` — canonical JSON contracts.
- `policy/` — shipped immutable policy seed.
- `sentinels/` — fixed diagnostic sentinel contract.
- `tests/` — unit, integrity, adversarial, and packaging tests.

## Security

Read [SECURITY.md](SECURITY.md) before enrolling an authority or promoting a release. A missing external release authority or missing signature is a deliberate blocker, not a setup detail Guardian may bypass.
