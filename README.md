<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="plugins/design-system-guardian/assets/brand/guardian-mark-dark.svg">
    <img src="plugins/design-system-guardian/assets/brand/guardian-mark.svg" width="180" alt="Design System Guardian">
  </picture>
</p>

<p align="center"><strong>Build and audit product UI using exact approved design-system identities—never silent substitutes.</strong></p>

# Design System Guardian

Design System Guardian is one private, updateable Codex marketplace plugin for teams whose design system is the source of truth. It combines strict provenance enforcement with UX reasoning, then audits the result independently.

## The rule that cannot be overwritten

> Only an exact, explicitly approved identity from the selected profile and pinned catalog may be selected. If an identity is genuinely missing, Guardian shows a conspicuous diagnostic sentinel. It never swaps in the closest color, a framework icon, an equal-looking literal, or a manually recreated component.

Policy precedence is `immutable policy -> evolving validators -> selected company profile -> pinned catalog`. Deny always wins. The immutable policy digest is `3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`.

## Two skills, one guardian

| Skill | Use it when |
| --- | --- |
| `build-with-design-system` | You want UX reasoning and implementation composed only from approved primitives, variants, icons, and tokens. |
| `audit-design-system` | You want a read-only compliance audit plus a separate UX/accessibility assessment lane. |

The CLI, schemas, Flutter adapter, sentinels, and release machinery are internal infrastructure, not additional skills.

## Build and audit workflow

1. Select one company profile and verify the host-owned policy anchor.
2. Refresh and pin one complete catalog snapshot for the whole task.
3. Record hierarchy, states, accessibility, and component intent.
4. Resolve every visual identity exactly and compose approved primitives only.
5. Read back the implementation, run the independent audit, and finalize sealed evidence.

Unavailable, incomplete, stale, ambiguous, conflicting, invalid, unsupported, and not-assessed states fail closed. They never become `missing`.

## Missing means conspicuous

Only proven absence in a fresh, complete snapshot creates `MISSING ICON`, `MISSING COLOR`, `MISSING TEXT STYLE`, or another fixed sentinel. Every sentinel includes request and policy evidence, cannot be promoted automatically, and sets `productionReady=false`.

## Architecture and trust boundary

Replaceable plugin code contains the two skills, validators, schemas, and adapters. The immutable anchor, profiles, catalogs, migrations, releases, and audit records live outside the plugin cache under `~/.design-system-guardian/`. One run pins one profile and one source-cut vector; profiles never blend.

Guardian reuses the existing Figma connection for discovery and refresh. Search results alone do not prove approval, and Guardian stores no second set of Figma credentials.

## Flutter-first support

Version 0.1.1 deeply audits Flutter through Dart analyzer evidence. It detects raw or unapproved colors, typography, icons, dimensions, effects, widgets, variants, motion, visual primitives, and suppression attempts. Projects without a supported adapter return `unsupported`; incomplete coverage never receives a green result.

The current source has no trusted host-attested UX/accessibility evaluator, so that lane remains `not_assessed` and blocks production readiness. Inaccessible approved assets are reported as design-system gaps; Guardian does not silently change them.

## Install and update from the private marketplace

```powershell
codex plugin marketplace add pv-vimalnair/design-system-guardian --ref main --json
codex plugin add design-system-guardian@pv-vimalnair-design-system-guardian --json
```

Before installing, compare the marketplace snapshot's full Git commit with the reviewed remote commit. A movable `main` reference alone is not release authority.

To refresh source later:

```powershell
codex plugin marketplace upgrade pv-vimalnair-design-system-guardian --json
```

Re-verify the fetched full commit, plugin version, immutable policy digest, and test evidence before accepting an update.

## CLI and exit codes

The portable `guardian` CLI exposes `doctor`, `profile validate`, `snapshot ingest`, `preflight`, `resolve`, `adapter flutter config`, `audit`, `finalize`, and `migrate`.

| Exit | Meaning |
| ---: | --- |
| 0 | Complete pass |
| 1 | Violation or sentinel |
| 2 | Invalid policy, configuration, or integrity |
| 3 | Unavailable, stale, or incomplete source |
| 4 | Unsupported adapter or incomplete/not-assessed coverage |

## Verification

```powershell
Push-Location plugins\design-system-guardian
..\..\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
..\..\.venv\Scripts\python.exe -m unittest discover -s adapters/flutter/tests -p "test_*.py"
Pop-Location
```

The publication candidate is expected to contain 251 core tests and 57 Flutter-adapter tests after the approved regression additions. The acceptance rule is all discovered tests passing; if coverage changes the count, this page must report the new exact result.

## Security and private data

Never commit profiles, catalog snapshots, Figma credentials, authority private keys, trust anchors, audit records, release signatures, or generated run evidence. Read [the plugin security policy](plugins/design-system-guardian/SECURITY.md) before enrolling an authority.

## Versioning and license

The source version is `0.1.1`. Source publication is not a trusted stable release: canary/stable promotion still requires the designated external authority, signed evidence, and the fixed external release-head provider. See [Updating and Releases](plugins/design-system-guardian/docs/UPDATING.md) and the [changelog](plugins/design-system-guardian/CHANGELOG.md).

Licensed under the [MIT License](LICENSE).
