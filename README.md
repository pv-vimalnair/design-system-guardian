<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="plugins/design-system-guardian/assets/brand/guardian-mark-dark.svg">
    <img src="plugins/design-system-guardian/assets/brand/guardian-mark.svg" width="180" alt="Design System Guardian">
  </picture>
</p>

<p align="center"><strong>Build and audit product UI using exact approved design-system identities - never silent substitutes.</strong></p>

# Design System Guardian

Design System Guardian is one public, updatable cross-agent package for teams whose design system is the source of truth. Codex, Claude Code, OpenClaw, Kimi Code, Qwen Code, terminal agents, Deep Code, and other Agent Skills-compatible hosts use the same two skills and the same deterministic Guardian core.

## The rule that cannot be overwritten

> Only an exact, explicitly approved identity from the selected profile and pinned catalog may be selected. If an identity is genuinely missing, Guardian shows a conspicuous diagnostic sentinel. It never swaps in the closest color, a framework icon, an equal-looking literal, or a manually recreated component.

Policy precedence is `immutable policy -> evolving validators -> selected company profile -> pinned catalog`. Deny always wins. The immutable policy digest remains `3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`.

## Two skills, one guardian

| Skill | Use it when |
| --- | --- |
| `build-with-design-system` | You want UX reasoning and implementation composed only from approved primitives, variants, icons, and tokens. |
| `audit-design-system` | You want an independent read-only compliance audit plus a separate UX/accessibility assessment. |

Setup, Figma read-back, the UX evaluator, CLI, schemas, Flutter adapter, sentinels, and release machinery are internal infrastructure. They are not extra skills or plugins.

## What is new in 0.3.6

- Installing v0.3.6 does not silently expand the v0.3.5 evaluator. The agent runs zero-write `guardian rules upgrade preview`, explains one exact local evaluator change in plain language, asks permission, and applies only the matching bundle.
- Zero-write `guardian rules list --profile <id>` reports the effective evaluator and each rule's capability without exposing rule prose, company paths, design content, or user data.
- After explicit evaluator-v2 authorization, the Flutter adapter can assess all six existing machine predicates, analyzer-proven `compilation_unit` and `widget_class` scope, and exact child, descendant, and sibling construction relations. Unknown or incomplete evidence remains `not_assessed`.
- Audit evidence now carries a separate Usage Rules lane alongside design-system compliance, UX/accessibility quality, and protected production authority. The lanes must agree and remain fail-closed.
- Generic Agent Skills installations have zero-write status values `current`, `update_required`, `reload_required`, and `invalid`. A watched-root failure restores the prior install and returns `host_restart_required`; restart that host and rerun the same verified update before claiming v0.3.6 is loaded.
- Every v0.3.2-v0.3.5 schema and evidence contract remains readable. Public Elo v6 evidence is synthetic; local scores, run results, and history stay outside Git.

Everything below from v0.3.2, v0.3.3, v0.3.4, and v0.3.5 remains part of v0.3.6:

- Permission-bound Safe Activation preserves externally signed rule approval and the exact v0.3.5 evaluator authorization; permission enables an evaluator but never approves rules.
- Preview-only usage-rule validation: `guardian rules validate` accepts explicit Figma description markers or a local rule artifact, validates the six supported machine predicates, and returns a deterministic report without changing Guardian or project state.
- Plug-and-play, permission-bound local setup: the agent checks readiness, explains one exact local change, asks once, and applies only the digest-bound setup after permission.
- Mandatory exact Figma binding and read-back for variables, text styles, component identities, variants, properties, and approved duplicate-file lineage. Visual equality is never evidence.
- A quick screen checkpoint after a completed screen and a final-flow UX/accessibility evaluation that rechecks every screen plus navigation, reachability, errors, recovery, and cross-screen state.
- The original three lanes remain intact: design-system compliance, UX/accessibility quality, and protected production authority. The new Usage Rules lane is additive and cannot hide or be hidden by them.
- Skills are portable; automatic routing is not. Installation on Claude Code, Kimi Code, OpenClaw, or a generic host does not create an always-on protected route. Guardian cannot prevent raw-tool bypass on those hosts. No sealed Guardian manifest means the result is not Guardian-approved.
- Fixed Figma API safeguards so common mutation-order and read-only-value traps fail clearly instead of encouraging agents to bypass Guardian.

The v0.3.4 `guardian rules validate` foundation remains read-only and preview-only, and its preview report is not consumed by audit or finalization. Version 0.3.5 retains its separately permissioned first two compilation-unit pairs. Version 0.3.6 requires another explicit permission before evaluator v2 may assess the expanded machine capability; none of these local paths creates protected production authority.

## Build and audit workflow

1. When a Guardian skill is explicitly invoked, the agent runs `guardian setup status` internally. If setup is needed, it validates the design-system-owner-provided local candidate with `guardian setup preview`, asks permission in plain language, and calls `guardian setup apply` only for that exact digest-bound candidate.
2. Select one company profile and refresh and pin one complete catalog snapshot for the whole task.
3. When approved usage rules need activation, preview the exact signed catalog v2, ask permission, and apply only its digest-bound bundle. Permission never substitutes for catalog approval.
4. Run `guardian rules list --profile <id>` read-only. If expanded evaluator coverage is needed, preview the evaluator-v2 upgrade, explain the exact local change in plain language, ask permission, and apply only its digest-bound bundle.
5. Record user intent, hierarchy, states, accessibility, component intent, and every planned approved visual identity.
6. Bind every Figma variable, text style, component, icon, variant, and property exactly; read the result back from the supported adapter. Compose approved primitives only.
7. Run the quick screen checkpoint when each screen is complete. Before handoff, rerun every screen in the final-flow evaluation.
8. Read back the implementation, run the independent audit, finalize sealed evidence, and report design-system, Usage Rules, UX/accessibility, and protected-authority lanes separately.

The setup candidate is prepared once by an authorized design-system owner and stays local. A public plugin cannot create a company catalog authority or approve discovered assets by itself. If the required candidate, source evidence, host capability, or protected authority is unavailable, Guardian reports the exact blocker instead of weakening the rule.

Unavailable, incomplete, stale, ambiguous, conflicting, invalid, unsupported, and not-assessed states fail closed. They never become `missing`.

## Missing means conspicuous

Only proven absence in a fresh, complete snapshot creates `MISSING ICON`, `MISSING COLOR`, `MISSING TEXT STYLE`, or another fixed sentinel. Every sentinel includes request and policy evidence, cannot be promoted automatically, and sets `productionReady=false`.

## Architecture and trust boundary

Replaceable plugin code contains the two skills, validators, schemas, and adapters. The immutable anchor, profiles, catalogs, migrations, releases, audit records, company design-system data, and generated Figma adapter configs live under `~/.design-system-guardian/`. Never place a Figma config or observation in the product tree or Git. One run pins one profile and one source-cut vector; profiles never blend.

Guardian reuses the host's existing Figma connection for discovery and refresh. It does not create a second credential store. Search results, screenshots, names, sampled hex values, and caller-written JSON do not prove approval.

### Duplicate Figma working files

Guardian works in an approved duplicate Figma working file when an `INSTANCE` still resolves to the exact approved published main component. The selected local profile explicitly authorizes the working file; refresh pins its source version and signs the exact file/node locator, remote component key, variant, properties, and empty unapproved-override set. The selection still resolves to the canonical design-system identity.

Cloned component definitions, detached instances, local components, changed overrides, names, screenshots, and visual similarity are invalid lineage. Guardian stops instead of guessing or creating a sentinel. Company Figma evidence remains local under `~/.design-system-guardian/` and never belongs in this public repository.

### Figma API safeguards

The Figma adapter requires agents to clear or bind a new frame's default fill, attach nodes to a layout parent before using `FILL`, clone and reassign read-only paint/effect collections, load fonts before text mutation, use asynchronous page/node APIs when required, and set component variants through supported component properties. A wrapper or node-kind mismatch is reported directly; it is never a reason to bypass exact binding.

## Flutter-first support

Version 0.3.6 keeps the deep Flutter analyzer adapter and Figma-native observation enforcement. With explicit evaluator-v2 permission it also assesses all six approved machine-rule predicates through exact analyzer-resolved identities, variants, construction relations, and honest `compilation_unit` or `widget_class` scope. Flutter diagnostics still detect raw or unapproved colors, typography, icons, dimensions, effects, widgets, variants, motion, visual primitives, and suppression attempts. Figma diagnostics require exact bound-variable, text-style, component-instance, variant/property, source-version, and duplicate-lineage evidence.

The built-in UX/accessibility evaluator derives status from evidence; callers cannot submit a pass. Screen checkpoints are diagnostic. The final-flow result is the complete UX lane input. An inaccessible approved asset is reported as a design-system gap; Guardian never silently changes its color, size, motion, or behavior.

Local Figma and UX evidence is diagnostic. Violations and gaps can fail immediately. Clean caller-carried Figma or UX evidence remains `not_assessed` until protected host attestation. Never label those local lanes `allowed`; `productionReady=false` remains mandatory. A project without a supported adapter returns `unsupported`.

## Install on Codex and other agents

| Host | Distribution path |
| --- | --- |
| Codex | `.agents/plugins/marketplace.json` and `.codex-plugin/plugin.json` |
| Claude Code | `.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json` |
| OpenClaw | The compatible Codex/Claude bundle; no duplicated runtime |
| Kimi Code | Repository-root `kimi.plugin.json` |
| Qwen Code | The two standard Agent Skills via its `~/.qwen/skills/` root and the integrity-bound generic installer |
| Terminal, Deep Code, and other compatible agents | The two standard Agent Skills plus the integrity-bound generic installer |

Codex installation:

```powershell
codex plugin marketplace add pv-vimalnair/design-system-guardian --ref main --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

See the [cross-agent installation guide](plugins/design-system-guardian/docs/INSTALLING.md) for Claude Code, OpenClaw, Kimi Code, Qwen Code, terminal agents, Deep Code, generic Agent Skills hosts, and updates.

For a generic Agent Skills host, fresh-host dependency setup is an explicit opt-in. The agent must explain the exact local change and obtain explicit permission before adding `--bootstrap-runtime` to the generic installer command. An absolute Python 3.11+ executable is still required as the bootstrap interpreter. The flag creates an isolated Guardian-owned virtual environment under `~/.design-system-guardian/runtimes/` and installs exactly `cryptography==46.0.7`, `cffi==2.1.0`, and `pycparser==3.0` from the bundled `requirements.txt` with dependency resolution disabled. Without the flag, the installer never creates a virtual environment or invokes `pip`. It first performs a read-only exact-version and import check in the selected host Python, while permitting unrelated host distributions; a mismatch blocks with an explicit permission-bound `--bootstrap-runtime` hint.

If the interpreter, virtual-environment creation, pinned installation, or runtime verification is unavailable or fails, installation blocks and the host remains `unsupported`; Guardian must fail closed. This diagnostic option does not create an always-on protected route.

Portable support means the host can load Agent Skills (or equivalent instructions), access bundled resources, execute the CLI, and provide supported evidence. It does not prove automatic invocation. Without an independently configured always-on protected route, use is diagnostic or `unsupported`, and Guardian cannot prevent raw-tool bypass. No sealed Guardian manifest means not Guardian-approved.

Before installing or updating, compare the fetched full Git commit with the reviewed remote commit. A movable `main` reference alone is not release authority.

## CLI and exit codes

The portable `guardian` CLI exposes permission-bound `setup status`, `setup preview`, and `setup apply`; `rules validate`, `rules activate preview`, `rules activate apply`, zero-write `rules list`, and permission-bound `rules upgrade preview` and `rules upgrade apply`; plus `doctor`, `profile validate`, `snapshot ingest`, `preflight`, `resolve`, `adapter flutter config`, `adapter figma config`, `ux checkpoint`, `audit`, `finalize`, `self-check`, profile-artifact `migrate`, and the `elo show`, `elo migrate`, `elo benchmark`, and `elo evaluate` commands.

| Exit | Meaning |
| ---: | --- |
| 0 | Complete pass issued only by a supported protected host attestation |
| 1 | Violation or sentinel |
| 2 | Invalid policy, configuration, or integrity |
| 3 | Unavailable, stale, or incomplete source |
| 4 | Unsupported adapter or incomplete/not-assessed coverage |

## Verification

```powershell
Push-Location plugins\design-system-guardian
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
.\.venv\Scripts\python.exe -m unittest discover -s adapters/flutter/tests -p "test_*.py"
Pop-Location
```

The acceptance rule is every discovered core, Figma, UX, onboarding, and Flutter-adapter test passing, both Agent Skills validating, every host manifest parsing, and each claimed host's status being reported honestly. An unavailable runtime check is not a pass.

## Security and private data

Never commit profiles, catalog snapshots, Figma credentials, authority private keys, trust anchors, audit records, local setup bundles, release signatures, or generated run evidence. Public updates are built from a clean source tree; local company and user data are not part of the release. Read [the plugin security policy](plugins/design-system-guardian/SECURITY.md) before enrolling an authority.

## Versioning and license

The source version is `0.3.6`. Source publication is not a trusted stable release: canary/stable promotion still requires the designated external authority, signed evidence, and the fixed external release-head provider. See [Updating and Releases](plugins/design-system-guardian/docs/UPDATING.md) and the [changelog](plugins/design-system-guardian/CHANGELOG.md).

Licensed under the [MIT License](LICENSE).
