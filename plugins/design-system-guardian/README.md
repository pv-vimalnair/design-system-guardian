# Design System Guardian

> Repository overview, installation, and product positioning: [root README](../../README.md).

Design System Guardian is one updatable cross-agent bundle with exactly two visible skills:

- `build-with-design-system` composes product UI with UX reasoning while enforcing exact approved identities.
- `audit-design-system` independently audits compliance and UX/accessibility without changing product files.

Setup, adapter dispatch, Figma collection, UX evaluation, schemas, sentinels, and release code are shared internal infrastructure. They are not additional skills or plugins.

## Immutable rule

Only exact, explicitly approved identities from one selected profile and one pinned, complete catalog snapshot may be selected. Similar names, nearest colors, equal-value literals, framework defaults, wrappers, substitutes, community assets, generated icons, manual recreation, rounding, and name-based guessing are not approval.

Only a proven `missing` result from a fresh, complete source may create a fixed diagnostic sentinel. A sentinel is conspicuous, remains outside the design system, and always sets `productionReady=false`. Unavailable, incomplete, stale, ambiguous, conflicting, invalid, unsupported, and not-assessed states never become `missing`.

Policy precedence is:

`immutable policy -> evolving validators -> selected profile -> pinned catalog`

Deny always wins. The unchanged create-once policy digest is:

`3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`

## Personal-local task and Figma-file selection

The default individual-user route starts fresh for every Guardian task and every target Figma file. The agent creates a new run ID, runs `guardian selection status --run-id <run-id>` without writing, discovers the complete published library candidates for the exact target file, and asks the user to mark every candidate **Use** or **Do not use**.

Through the existing Figma connection, discovery must also carry complete one-to-one catalog read-back. Every token must match one exact selected variable or style binding, resolved content, stable key, and source version; every component and icon must match one exact published file, node ID, asset key, source version, design contract, and Code Connect mapping. A missing proof, duplicate locator, excluded source, or content/version mismatch blocks preview before Guardian writes local state. Matching caller-carried catalog and read-back remain consistent local guidance, not independently proven Figma provenance.

The agent validates the discovery with `guardian selection preview --run-id <run-id> --input <discovery.json>`. Preview is zero-write and returns the exact task, project, target-file, library-decision, catalog, and adapter binding that needs confirmation. Only after the user confirms may the agent run `guardian selection apply --input <permission-bound-selection.json>`.

At least one published library must be selected. Every unselected library is forbidden for that run. Guardian never silently inherits a choice from another task, client, project, run, duplicate, or Figma file. A changed target file identity or version requires a new run and a new confirmation before visual work.

Personal selection records, file identities, profiles, catalogs, and snapshots stay in account-owned Guardian local state. Library names may be shown only in the current local **Use** / **Do not use** interaction; the evidence never enters the plugin package, Git, public Elo fixtures, telemetry, or generated product files. This local permission authorizes only the exact personal task selection; it does not approve enterprise Usage Rules or create protected production authority.

The read-back is intentionally labeled `unprotected_caller_carried`: Guardian verifies exact coverage and consistency, while the host's existing Figma connection supplies the local evidence. It is not an independent company signature, cannot make `productionReady=true`, and does not claim protection from a same-account process that bypasses Guardian.

## Optional signed enterprise setup

Organizations may opt into the unchanged externally signed enterprise route. An agent first runs `guardian setup status` without modifying anything. When setup is needed, an authorized design-system owner supplies one local candidate containing the catalog authority public key, exact profile, and signed complete catalog. The agent runs `guardian setup preview --input <candidate.json>`, explains the exact profile, Figma allowlist, and digests in plain language, and asks the user once.

Only after explicit permission does the agent add the preview's exact digest binding and run `guardian setup apply --input <permitted-bundle.json>`. Apply validates in isolation and promotes the complete local state atomically. It never invents a catalog authority, approves Figma discovery, replaces a different profile revision, or uploads company data.

Ordinary users should not have to copy commands. The two skills perform this sequence internally and surface only the permission request or exact blocker.

## Preview-only usage-rule validation

`guardian rules validate` accepts either explicit `[dsg-rule ...]...[/dsg-rule]` markers from a Figma description or a local JSON rule artifact. Unmarked prose is not treated as an enforceable rule. The validator supports the six machine predicates defined by the v0.3.4 contract and reports invalid, unknown, or unassessed identities without guessing.

This foundation is read-only and preview-only: it writes no Guardian or project state, reports `localChangesPerformed=false` and `productionReady=false`, and keeps missing identity coverage `not_assessed`. Rule results are not consumed by audit or finalization in v0.3.4 and cannot authorize production.

## Permission-bound safe activation

Version 0.3.5 keeps the preview path above and adds a separate local activation path. The agent first runs `guardian rules activate preview --profile <id> --input <signed-catalog-v2.json>`, explains the exact policy/profile/catalog/rules/evaluator binding, and asks the user for permission. Only the resulting exact permission-bound bundle may be passed to `guardian rules activate apply --input <permission-bound-bundle.json>`.

Permission enables the evaluator; it does not approve rules. Rules are accepted only from the selected profile's externally signed catalog authority. Activation creates an append-only v2 rule snapshot and sequence in a parallel namespace; it does not edit or replace the existing v1 profile, snapshots, approval sequences, or current pointer.

Version 0.3.5 enforces only `forbidden_identity_in_scope` + `compilation_unit` and `max_instances_per_scope` + `compilation_unit`. Other valid rules remain stored and previewable but `not_assessed` until v0.3.6. Once v2 evidence exists, Guardian never falls back to v1 if the v2 head or evidence is unavailable, corrupt, incomplete, or discontinuous.

## Explicit evaluator-v2 permission and rule inventory

Installing v0.3.6 does not expand the permission above. The agent first runs `guardian rules list --profile <id>` read-only. The canonical result lists the effective evaluator, rule IDs/classes, capability status, fixed reason codes, and active/not-assessed/informative counts without printing rule prose, company paths, design content, or user data.

When expanded coverage is needed, the agent runs `guardian rules upgrade preview --profile <id>` without writing. It explains in plain language that Guardian can now check all six approved machine-rule types, including analyzer-proven `widget_class` scope, and asks whether it may save that exact local evaluator permission for the selected profile. Only after explicit permission may the exact bundle be passed to `guardian rules upgrade apply --input <permission-bound-bundle.json>`. The user does not copy files, hashes, or commands.

A valid evaluator-v2 authorization covers all six existing machine predicates, `compilation_unit` and `widget_class` scope where defined, and exact child, descendant, and sibling relations. It does not approve rules, identities, or assets. Without it, Guardian keeps the v0.3.5 evaluator and reports newly supported capabilities as `not_assessed`. The inherited v0.3.6 machine-rule lane leaves judgment rules `not_assessed` until the v0.3.7 assessment evaluates them; incomplete instances remain `not_assessed`, and informative rules remain non-gating.

## Exact-run subjective judgment decisions

Version 0.3.7 completes subjective judgment assessments and explains every finding before asking the user to choose. Raw findings always remain visible. The effective projection separately shows whether selected conflicts passed through a user-approved exception.

The agent runs these four exact portable forms for the user:

    guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>
    guardian judgment apply --input <granted-bundle.json>
    guardian judgment status --profile <profile-id> --run-id <run-id>
    guardian judgment revoke --input <granted-revocation.json>

Preview and status are read-only. Apply and revoke require explicit permission for the exact local operation. The optional reason is recorded as context, not authority. Approval is limited to selected conflicts in one exact run and is reevaluated for every new screen or flow. It is never reused for a future run, version, or duplicate file; revocation appends a new record without deleting history.

Judgment exceptions never override design-system compliance, Usage Rules, sentinels, stale or incomplete evidence, unsupported or not-assessed coverage, or protected production authority. An unprotected host remains non-authoritative. Assessments, reasons, decisions, revocations, and company evidence stay local and never enter Git, Elo, or telemetry.

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

The final version 2 `guardian audit` accepts `uxEvidence` and reruns the final-flow evaluation across every selected screen plus navigation, reachability, errors, recovery, and cross-screen state. A proven violation or gap can fail the run. Clean personal-local Figma or Flutter coverage and caller-carried UX evidence remain `not_assessed` until protected host attestation.

Guardian reports four independent lanes:

1. design-system compliance;
2. Usage Rules compliance;
3. UX/accessibility quality;
4. protected production authority.

The Usage Rules lane is `allowed` only when every active gating machine rule is fully assessed without violation. Exact violations produce `conflict`; incomplete relationships, judgment rules, and uncovered gating work remain `not_assessed`. Informative rules do not gate. The inherited design-system projection and the Usage Rules lane must agree or the result is invalid.

A compliant design can still fail Usage Rules or UX, and an accessible unauthorized substitute still fails design-system compliance. Local Figma, personal-local Flutter, and UX evidence is diagnostic: violations and gaps can fail, while clean caller-carried evidence remains `not_assessed`. Protected production authority remains unavailable and `productionReady=false` without protected host or CI attestation.

An inaccessible approved asset is a design-system gap. Guardian never silently changes its color, size, motion, or behavior.

## Flutter compatibility

Version 2 audit requests also support `adapter: "flutter"`, `adapterEvidence: null`, and the exact project root. With explicit evaluator-v2 permission, Guardian assesses all six machine predicates through analyzer-resolved identities, variants, construction relations, and honest `compilation_unit` or `widget_class` scope. Guardian owns analyzer execution, derives a run-bound allowlist, verifies the profile-bound Dart SDK and package closure, hashes source and analyzer input, analyzes an external staging copy, requires one attestation per compilation unit, scans suppressions, and seals the result.

Backward-compatible version 1 Flutter audit requests remain readable. A project or host without a supported adapter returns `unsupported`; incomplete coverage never passes.

## Portable CLI

The CLI implementation is `scripts/guardian.py`. Protected gating requires an authority-bound absolute interpreter or signed standalone executable. A private-pilot diagnostic may use a host-supplied absolute Python executable after recording its path and digest, but it cannot grant production authority. Convenience wrappers deliberately exit `4` instead of discovering Python from `PATH`.

The command surface is:

- `selection status`, `selection preview`, `selection apply`
- `setup status`, `setup preview`, `setup apply`
- `doctor`
- `profile validate`
- `snapshot ingest`
- `preflight`
- `resolve`
- `rules validate`
- `rules activate preview`, `rules activate apply`
- `rules list`
- `rules upgrade preview`, `rules upgrade apply`
- `judgment preview`, `judgment apply`, `judgment status`, `judgment revoke`
- `adapter flutter config`
- `adapter figma config`
- `ux checkpoint`
- `audit`
- `finalize`
- `self-check`
- `migrate`
- `elo show`, `elo migrate`, `elo benchmark`, `elo evaluate`

Exit codes are deterministic: `1` reports violations or sentinels, `2` policy/configuration/integrity failure, `3` unavailable/stale/incomplete source, and `4` unsupported or not-assessed coverage. Exit `0` requires supported protected host attestation; clean personal-local, enterprise, or otherwise caller-carried Figma or UX evidence cannot produce it.

## Trust and private data

Replaceable bundle code contains validators, schemas, adapters, and skills. Private state lives outside every agent's replaceable plugin cache under `~/.design-system-guardian/`: policy trust, public authorities, isolated company profiles, immutable snapshots, run evidence, migrations, release history, and local Elo history.

Guardian reuses the host's existing Figma connection and adds no credential store. Profiles, design-system data, setup candidates, snapshots, observations, audit records, judgment assessments, reasons, decisions, revocations, prompts, product source, credentials, and user activity must never enter this public repository, Git, Elo, telemetry, or a plugin update.

No sealed Guardian manifest means the work is not Guardian-approved.

## Cross-agent installation

Codex, Claude Code, OpenClaw, and Kimi Code use host manifests over this same directory. Qwen Code, terminal agents, Deep Code, and generic Agent Skills hosts use the integrity-bound installer without duplicating `guardian_core`. See [Installing on Agent Hosts](docs/INSTALLING.md).

On generic hosts, `--bootstrap-runtime` is opt-in. The agent must explain the exact local change and obtain explicit permission before using it. An absolute Python 3.11+ executable remains required. The flag creates an isolated Guardian-owned virtual environment under `~/.design-system-guardian/runtimes/` and installs exactly `cryptography==46.0.7`, `cffi==2.1.0`, and `pycparser==3.0` from the bundled `requirements.txt` with dependency resolution disabled; without the flag, the installer never creates a virtual environment or invokes `pip`. It first performs a read-only exact-version and import check in the selected host Python, while permitting unrelated host distributions; a mismatch blocks with an explicit permission-bound `--bootstrap-runtime` hint.

If bootstrap creation, pinned installation, or verification is unavailable or fails, installation blocks and the host remains `unsupported`; Guardian must fail closed. This diagnostic bootstrap does not create an always-on protected route.

Generic hosts may run `python <reviewed-package>/scripts/install_agent_skills.py --target-root <host-skill-root> --status` without writing. The result is `current`, `update_required`, `reload_required`, or `invalid`. If a Windows watcher blocks atomic promotion, Guardian restores the prior installation and reports `reload_required` with `host_restart_required`; close or restart that exact host, rerun the same verified update, reload or start a new session, and read back the version and two skills before claiming success.

Skills are portable; automatic routing is not. Installing them on Claude Code, Kimi Code, OpenClaw, or a generic host does not create an always-on protected route. A host is enforceable only when it independently invokes Guardian before raw tools and protects the resulting evidence. Otherwise use is diagnostic or `unsupported`, and Guardian cannot prevent raw-tool bypass.

## Release and update model

Plugin source updates use reviewed SemVer and deterministic migrations. Release authority remains separate from source distribution:

- production code verifies one externally held Ed25519 release authority;
- Guardian has no private-key generator, import, or signing command;
- `canary` and `stable` retain independent contiguous sequences;
- stable requires the exact canary version, full commit, artifact digest, policy digest, schema, and compatibility range;
- rollback is a new signed restoration and never rewrites history;
- private catalogs, trust anchors, run evidence, and release state remain outside the replaceable cache.

A marketplace, bundle, generic-skill, or cachebuster installation is an unsigned source installation. In 0.3.8 the external/WORM release-head provider remains an unconditional compile-time blocker. Source publication does not claim a trusted canary or stable promotion.

Version 0.3.8 adds the default personal-local, per-task and per-Figma-file **Use** / **Do not use** selection flow. It never reuses an earlier selection silently, blocks visual work when no library is selected, forbids every unselected library, and leaves the signed enterprise route unchanged. Personal selection and discovery evidence remain local.

Version 0.3.5 adds permission-bound Safe Activation for the two documented compilation-unit pairs. It preserves the complete v0.3.2-v0.3.4 surface, and local activation still cannot create protected production authority.

Version 0.3.6 adds a separately permissioned evaluator-v2 sidecar, zero-write rule inventory, complete machine-rule capability, a separate Usage Rules lane, and recoverable host reload status without rewriting v0.3.2-v0.3.5 evidence.

Version 0.3.7 adds complete subjective judgment assessments, selected exact-run conflict exceptions, optional reasons, status read-back, and append-only revocation without rewriting v0.3.2-v0.3.6 evidence. Public Elo cases are synthetic; local score, benchmark results, assessments, reasons, decisions, and append-only history stay outside Git.

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
