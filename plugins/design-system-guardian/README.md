# Design System Guardian

> Repository overview, installation, and product positioning: [root README](../../README.md).

Design System Guardian is one updatable cross-agent bundle with exactly two visible skills:

- `build-with-design-system` composes product UI with UX reasoning while enforcing exact approved identities.
- `audit-design-system` independently audits compliance and UX/accessibility without changing product files.

Setup, adapter dispatch, Figma collection, UX evaluation, schemas, sentinels, and release code are shared internal infrastructure. They are not additional skills or plugins.

## Immutable rule

Only exact, explicitly approved identities from one selected company profile and one pinned, complete catalog snapshot may be selected. Similar names, nearest colors, equal-value literals, framework defaults, wrappers, substitutes, community assets, generated icons, manual recreation, rounding, and name-based guessing are not approval.

Only a proven `missing` result from a fresh, complete source may create a fixed diagnostic sentinel. A sentinel is conspicuous, remains outside the design system, and always sets `productionReady=false`. Unavailable, incomplete, stale, ambiguous, conflicting, invalid, unsupported, and not-assessed states never become `missing`.

Policy precedence is:

`immutable policy -> evolving validators -> selected company profile -> pinned catalog`

Deny always wins. The unchanged create-once policy digest is:

`3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`

## Permission-bound setup

An agent first runs `guardian setup status` without modifying anything. When setup is needed, an authorized design-system owner supplies one local candidate containing the catalog authority public key, exact profile, and signed complete catalog. The agent runs `guardian setup preview --input <candidate.json>`, explains the exact profile, Figma allowlist, and digests in plain language, and asks the user once.

Only after explicit permission does the agent add the preview's exact digest binding and run `guardian setup apply --input <permitted-bundle.json>`. Apply validates in isolation and promotes the complete local state atomically. It never invents a catalog authority, approves Figma discovery, replaces a different profile revision, or uploads company data.

Ordinary users should not have to copy commands. The two skills perform this sequence internally and surface only the permission request or exact blocker.

## Figma evidence

`guardian adapter figma config --profile <id> --run-id <id> --output <absolute-guardian-local-state-config.json>` derives the run-bound collector contract. The output must stay inside Guardian local state under `~/.design-system-guardian/`; never place it in the product tree, repository, or Git staging. The supported Figma collector reads the selected nodes back through the Plugin API. A version 2 audit accepts exact input shaped as:

```json
{
  "schemaVersion": 2,
  "adapter": "figma",
  "projectRoot": "<exact-local-workspace-root>",
  "resolutions": [],
  "uxEvidence": {"target": {}, "observations": []},
  "adapterEvidence": {}
}
```

The `projectRoot` must match the exact local workspace bound at preflight. The actual `adapterEvidence` must be the fixed collector observation bound to the policy, profile, snapshot, source cut, adapter config, file version, and selected nodes. Caller-written status is not accepted. Guardian verifies:

- variable aliases by stable key, type, collection, and mode;
- exact text-style binding or complete text-range bindings;
- actual `INSTANCE` nodes, remote main-component keys, variants, component properties, and empty unapproved overrides;
- exact source file version and node locator;
- raw, sampled, inferred, or equal-looking values as violations.

### Approved duplicate working files

A duplicate working file is supported only when its exact `INSTANCE` remains linked to the approved published main component. The local profile authorizes the working file, and the signed snapshot pins its source version, file/node locator, canonical component key, variant, properties, and override evidence. Detached instances, cloned/local component definitions, changed overrides, names, screenshots, hashes, and visual similarity are invalid lineage.

### Fixed Plugin API safeguards

The build skill requires the host agent to use these established safeguards; the collector remains read-only and exposes off-system residue where it is observable:

- clear or bind a new frame's default white fill;
- attach a node to a layout parent before setting a fill layout mode;
- clone and reassign read-only paint, effect, and other Plugin API collections;
- load every font before changing text;
- use asynchronous page/node APIs when required by the document mode;
- read and set variants with supported component properties and `setProperties`;
- verify actual node and component object kinds before instantiation or mutation.

A Plugin API mismatch blocks or reports the affected operation. It never authorizes a raw fallback. Read-back cannot prove historical call ordering or font loading unless the host supplies separately attested execution evidence, so those checks remain `not_assessed` rather than guessed.

## UX/accessibility evaluation

`guardian ux checkpoint --profile <id> --run-id <id> --input <json>` accepts `{schemaVersion:1,target,observations}` for a non-authoritative quick screen checkpoint. The evaluator derives each check result; callers cannot submit a pass.

The final version 2 `guardian audit` accepts `uxEvidence` and reruns the final-flow evaluation across every selected screen plus navigation, reachability, errors, recovery, and cross-screen state. A proven violation or gap can fail the run. Clean caller-carried Figma or UX evidence remains `not_assessed` until protected host attestation.

Guardian reports three independent lanes:

1. design-system compliance;
2. UX/accessibility quality;
3. protected production authority.

A compliant design can still fail UX, and an accessible unauthorized substitute still fails design-system compliance. Local Figma and UX evidence is diagnostic: violations and gaps can fail, but clean evidence cannot pass. Never label those local lanes `allowed`; without protected host or CI attestation they remain `not_assessed` and `productionReady=false`.

An inaccessible approved asset is a design-system gap. Guardian never silently changes its color, size, motion, or behavior.

## Flutter compatibility

Version 2 audit requests also support `adapter: "flutter"`, `adapterEvidence: null`, and the exact project root. Guardian owns analyzer execution, derives a run-bound allowlist, verifies the profile-bound Dart SDK and package closure, hashes source and analyzer input, analyzes an external staging copy, requires one attestation per compilation unit, scans suppressions, and seals the result.

Backward-compatible version 1 Flutter audit requests remain readable. A project or host without a supported adapter returns `unsupported`; incomplete coverage never passes.

## Portable CLI

The CLI implementation is `scripts/guardian.py`. Protected gating requires an authority-bound absolute interpreter or signed standalone executable. A private-pilot diagnostic may use a host-supplied absolute Python executable after recording its path and digest, but it cannot grant production authority. Convenience wrappers deliberately exit `4` instead of discovering Python from `PATH`.

The command surface is:

- `setup status`, `setup preview`, `setup apply`
- `doctor`
- `profile validate`
- `snapshot ingest`
- `preflight`
- `resolve`
- `adapter flutter config`
- `adapter figma config`
- `ux checkpoint`
- `audit`
- `finalize`
- `self-check`
- `migrate`
- `elo show`, `elo migrate`, `elo benchmark`, `elo evaluate`

Exit codes are deterministic: `1` reports violations or sentinels, `2` policy/configuration/integrity failure, `3` unavailable/stale/incomplete source, and `4` unsupported or not-assessed coverage. Exit `0` requires supported protected host attestation; clean caller-carried Figma or UX evidence cannot produce it.

## Trust and private data

Replaceable bundle code contains validators, schemas, adapters, and skills. Private state lives outside every agent's replaceable plugin cache under `~/.design-system-guardian/`: policy trust, public authorities, isolated company profiles, immutable snapshots, run evidence, migrations, release history, and local Elo history.

Guardian reuses the host's existing Figma connection and adds no credential store. Profiles, design-system data, setup candidates, snapshots, observations, audit records, prompts, product source, credentials, and user activity must never enter this public repository or a plugin update.

No sealed Guardian manifest means the work is not Guardian-approved.

## Cross-agent installation

Codex, Claude Code, OpenClaw, and Kimi Code use host manifests over this same directory. Deep Code and generic Agent Skills hosts use the integrity-bound installer without duplicating `guardian_core`. See [Installing on Agent Hosts](docs/INSTALLING.md).

On generic hosts, `--bootstrap-runtime` is opt-in. The agent must explain the exact local change and obtain explicit permission before using it. An absolute Python 3.11+ executable remains required. The flag creates an isolated Guardian-owned virtual environment under `~/.design-system-guardian/runtimes/` and installs exactly `cryptography==46.0.7`, `cffi==2.1.0`, and `pycparser==3.0` from the bundled `requirements.txt` with dependency resolution disabled; without the flag, the installer never creates a virtual environment or invokes `pip`. It first performs a read-only exact-version and import check in the selected host Python, while permitting unrelated host distributions; a mismatch blocks with an explicit permission-bound `--bootstrap-runtime` hint.

If bootstrap creation, pinned installation, or verification is unavailable or fails, installation blocks and the host remains `unsupported`; Guardian must fail closed. This diagnostic bootstrap does not create an always-on protected route.

Skills are portable; automatic routing is not. Installing them on Claude Code, Kimi Code, OpenClaw, or a generic host does not create an always-on protected route. A host is enforceable only when it independently invokes Guardian before raw tools and protects the resulting evidence. Otherwise use is diagnostic or `unsupported`, and Guardian cannot prevent raw-tool bypass.

## Release and update model

Plugin source updates use reviewed SemVer and deterministic migrations. Release authority remains separate from source distribution:

- production code verifies one externally held Ed25519 release authority;
- Guardian has no private-key generator, import, or signing command;
- `canary` and `stable` retain independent contiguous sequences;
- stable requires the exact canary version, full commit, artifact digest, policy digest, schema, and compatibility range;
- rollback is a new signed restoration and never rewrites history;
- private catalogs, trust anchors, run evidence, and release state remain outside the replaceable cache.

A marketplace, bundle, generic-skill, or cachebuster installation is an unsigned source installation. In 0.3.3 the external/WORM release-head provider remains an unconditional compile-time blocker. Source publication does not claim a trusted canary or stable promotion.

The Usage Rules Lane is deferred to version 0.3.4.

See [Trusted Execution](docs/TRUSTED_EXECUTION.md), [Updating and Releases](docs/UPDATING.md), and [Release Evidence Contract](docs/RELEASES.md).

## Repository map

- `.codex-plugin/plugin.json` - Codex metadata.
- `.claude-plugin/plugin.json` - Claude Code metadata.
- `../../kimi.plugin.json` - Kimi Code metadata.
- `skills/` - exactly the two visible Agent Skills.
- `guardian_core/` - deterministic setup, policy, catalog, audit, UX, migration, and release enforcement.
- `adapters/figma/` - Figma collector contract and fixed Plugin API safeguards.
- `adapters/flutter/` - Flutter analyzer adapter and fixed sentinel widget.
- `schemas/` - canonical JSON contracts.
- `policy/` - immutable policy seed.
- `sentinels/` - fixed diagnostic sentinel contract.
- `tests/` - unit, integrity, adversarial, privacy, and packaging tests.

## Security

Read [SECURITY.md](SECURITY.md) before enrolling an authority or promoting a release. Missing external authority, source evidence, signature, or protected execution is a blocker, not a setup detail Guardian may bypass.
