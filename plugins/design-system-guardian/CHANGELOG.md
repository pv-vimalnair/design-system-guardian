# Changelog

All notable changes use SemVer. Entries describe source candidates. Local signed history under `~/.design-system-guardian/releases/` is a non-authoritative projection; actual promotion status requires the canonical external/WORM latest head plus matching signed release evidence.

## 0.3.6 - 2026-07-27 - Permissioned machine-rule enforcement

### Added

- Added separate `guardian rules upgrade preview` and permission-bound `guardian rules upgrade apply` commands. Installing v0.3.6 alone does not expand the retained v0.3.5 evaluator permission.
- Added zero-write `guardian rules list` with canonical privacy-safe rule IDs, classes, capability states, reason codes, evaluator binding, and summary counts.
- Added deterministic Flutter coverage for all six existing machine predicates, analyzer-proven `widget_class` scope, and exact child, descendant, and sibling construction relations after evaluator-v2 authorization.
- Added a separate sealed Usage Rules audit lane while preserving the inherited design-system projection and the independent UX/accessibility and protected-authority lanes.
- Added zero-write generic installation status and recoverable `reload_required` / `host_restart_required` guidance for watched Agent Skills roots.
- Added synthetic public weighted Elo v6 cases for evaluator permission, no implicit upgrade, complete capability, Usage Rules privacy, rule inventory, and reload status.

### Compatibility, security, and privacy

- Preserved every v0.3.2-v0.3.5 public schema, reader, rule snapshot, evaluator permission, release record, and exactly-two-skill package contract. No historical evidence is rewritten.
- Permission changes evaluator capability only; externally signed catalog authority still approves rules. Missing permission, incomplete relationships, unsupported adapters, judgment rules, or source blockers remain fail-closed and never become a guessed pass.
- Corrected the executable adapter floor to Flutter 3.41+/Dart 3.11+, as required by the already-pinned analyzer 14 line, and added official full-commit Flutter checks for package resolution, formatting, analysis, and Dart tests on Windows and Ubuntu.
- Company profiles, catalogs, rules, source locators, prompts, product source, run evidence, local Elo scores/results/history, credentials, and user activity remain outside the public repository and package.
- Codex, Claude Code, OpenClaw, Kimi Code, Qwen Code, terminal, and generic Agent Skills surfaces continue to use one canonical Guardian core and the same two visible skills.

### Promotion status

- This is a public source release candidate. It is not a trusted canary or stable promotion because the fixed external/WORM release-head provider and protected production authority remain unavailable.

## 0.3.5 - 2026-07-26 - Permission-bound Safe Activation

### Added

- Added read-only `guardian rules activate preview` and permission-bound `guardian rules activate apply` for an exact externally signed catalog v2 candidate.
- Added append-only rule snapshots, approval-sequence continuation, and a sealed rule high-water pointer in a parallel v2 namespace.
- Added Flutter enforcement for `forbidden_identity_in_scope` and `max_instances_per_scope` at `compilation_unit` scope; other valid rules remain preserved and `not_assessed` until v0.3.6.
- Added strict SemVer no-downgrade protection to the generic two-skill installer and weighted public Elo v5 cases for activation correctness, v1 preservation, coverage, authority separation, and downgrade safety.

### Compatibility, security, and privacy

- Preserved every v0.3.2 duplicate-file, v0.3.3 setup/Figma/UX, and v0.3.4 preview-rule capability, schema, and skill contract. Existing profile v1, snapshot v1, approval sequence, current pointer, run pin, and Flutter config v1 evidence is never migrated in place.
- Permission enables the evaluator but does not approve rules. Rule content still requires the selected profile's pinned external catalog-authority signature.
- Once v2 rule evidence exists, unavailable, malformed, incomplete, stale, replayed, or discontinuous v2 state blocks; protected rule work never falls back to v1.
- Company catalogs, rules, profiles, run data, and user content remain local and are excluded from public source, artifacts, benchmarks, and update history.

### Promotion status

- This is a public source release candidate. It is not a trusted canary or stable promotion because the fixed external/WORM release-head provider and protected production authority remain unavailable.

## 0.3.4 - 2026-07-26 - Preview-only usage-rule foundation

### Added

- Added `guardian rules validate` for explicit Figma description markers and local rule artifacts, with strict parsing and six supported machine predicates.
- Added canonical rule and validation-report schemas plus deterministic privacy-preserving result codes.
- Expanded the canonical public Elo benchmark suite with v4 rule, privacy, and release-contract cases.

### Security and privacy

- Rule validation is read-only and preview-only. It writes no Guardian or project state. Its canonical report does not echo rule statements, source paths, or Figma identities and always reports `localChangesPerformed=false` and `productionReady=false`.
- Missing identity coverage remains `not_assessed`; invalid or incomplete inputs fail closed. Rule results are not consumed by audit or finalization in this release.
- The immutable policy digest, company-state boundary, and exactly two visible skills are unchanged. Version 0.3.4 requires no state migration.

### Promotion status

- This is a public source release candidate. It is not a trusted canary or stable promotion because the fixed external/WORM release-head provider and protected production authority remain unavailable.

## 0.3.3 - 2026-07-26 - Plug-and-play Figma and UX enforcement

### Added

- Added agent-driven `guardian setup status`, `setup preview`, and permission-bound `setup apply`, so ordinary users approve one plain-language local change instead of manually installing trust files.
- Added exact Figma Plugin API read-back for bound variables, text styles, component instances, variants, properties, source versions, and signed duplicate-working-file lineage.
- Added a non-authoritative quick screen checkpoint and a final-flow UX/accessibility evaluator whose result is derived from evidence rather than caller-authored status.
- Added version 2 audit routing for Flutter and Figma while preserving backward-compatible version 1 Flutter requests.
- Added portable two-skill guidance while stating that installation does not create automatic routing, unprotected hosts cannot prevent raw-tool bypass, and no sealed Guardian manifest means not Guardian-approved.

### Fixed

- Split design-system compliance, UX/accessibility quality, and protected production authority so a failure or unknown in one lane cannot be projected as success in another.
- Documented fixed Figma API safeguards for default frame fills, layout-parent ordering, read-only collections, font loading, async APIs, component properties, and node-kind verification.
- Replaced manual onboarding instructions with a digest-bound preview-and-permission flow and clear unsupported/source blockers.
- Hardened the audit and attestation boundary so direct local Figma or UX positive claims cannot create false-green lanes, while proven violations and gaps remain visible.
- Hardened generic installation with an exact three-package lock, dependency resolution disabled, read-only host verification, and symlink/junction/reparse rejection for Guardian-owned runtime storage.

### Security and privacy

- The immutable policy digest and exactly two visible skills are unchanged.
- Company profiles, catalogs, setup candidates, generated Figma configs/observations, audit evidence, prompts, product source, credentials, user activity, and local Elo history remain inside Guardian local state and are excluded from product/Git paths and public artifacts.
- Local Figma and UX evidence is diagnostic: violations and gaps can fail, but clean caller-carried evidence remains `not_assessed` until protected host/CI attestation, with `productionReady=false`.
- The Usage Rules Lane remains out of scope and is planned for 0.3.4.

### Promotion status

- This is a public source release candidate. It is not a trusted canary or stable promotion because the fixed external/WORM release-head provider and protected production authority remain unavailable.

## 0.3.2 - 2026-07-24 - Watched-root installer compatibility

### Fixed

- Stages and backs up generic Agent Skills beside the host's watched skill root, preventing Windows skill watchers from locking transient `SKILL.md` files during atomic installation.
- Preserves the same journaled rollback, package digest, Python digest, policy digest, and modified-install refusal guarantees.

## 0.3.1 - 2026-07-24 - Duplicate working-file provenance

### Added

- Added exact signed bindings for duplicated Figma working-file instances that remain linked to approved published main components.
- Added strict `figmaInstance` resolution evidence covering the pinned file version and exact node locator.

### Security

- Detached instances, cloned or local component definitions, modified overrides, and visual/name similarity remain invalid and never create a missing sentinel.
- The immutable policy digest, two-skill contract, and local-only company data boundary are unchanged.

## 0.3.0 - 2026-07-24 - Evidence-driven evolution candidate

### Added

- Added an automatic sealed post-run self-check that records what worked, what failed, and fixed attribution reason codes without storing prompts, product source, credentials, or general user activity.
- Added an explicit permission gate before Plugin Evolution Manager or an equivalent compatible-agent review may change Guardian.
- Added executable weighted Guardian Elo from 1 to 2000, with public synthetic benchmarks, additive immutable coverage, controlled regression evidence, and a 200-point per-release cap.
- Added a clean-public-release gate over committed bytes, reachable history, local design-system identifiers and file hashes, Git modes, and authenticated prior-suite continuity.

### Changed

- Added `guardian elo migrate` for exact five-file 0.2 trust homes; it preserves existing authorities, creates sealed score-1 genesis, and reports the new ledger ID and continuity reset. Total local erasure remains indistinguishable from a genuine pre-Elo home.
- Made an interrupted Elo append recover a one-entry head lag exactly once; an exact retry is idempotent, while different retry evidence recovers the head and then fails closed.
- Synchronized Codex, Claude Code, Kimi Code, Flutter, generic Agent Skills, and Guardian runtime metadata at version 0.3.0.
- Kept company profiles, catalogs, snapshots, run evidence, and Elo history local under `~/.design-system-guardian/`; public source remains a clean implementation and synthetic benchmark package.

### Promotion status

- The authenticated 0.2.0 package remains the immutable Elo genesis at score 1; measured progress is stored only in the sealed local ledger.
- This public source candidate is not a signed canary or stable promotion. The fixed external/WORM release-head provider and trusted UX/accessibility evaluator remain deliberate blockers.
- The immutable policy digest and exactly two visible skills are unchanged.

## 0.2.0 - 2026-07-23 - Cross-agent distribution candidate

### Added

- Added Claude Code plugin and marketplace manifests over the canonical two-skill package.
- Added a Kimi Code manifest that points to the same nested canonical skills.
- Added compatible-bundle installation for OpenClaw without a duplicated native runtime.
- Added an integrity-bound generic installer for Deep Code and other Agent Skills-compatible hosts.

### Promotion status

- Codex and Claude packaging is locally validated. OpenClaw bundle structure is validated but its runtime smoke remains unverified; Kimi Code and Deep Code remain structurally validated until those CLIs are available.
- Cross-agent source publication does not create a trusted canary or stable release.
- The immutable policy digest and fail-closed production blockers are unchanged.

## 0.1.1 - 2026-07-23 - Private marketplace publication candidate

### Changed

- Added private GitHub marketplace packaging and the sealed G2 Token G identity.
- Made trusted-time tests, sentinel bytes, and verified Dart executable evidence deterministic across supported platforms.
- Replaced pilot-company-named synthetic fixtures with portable example-company fixtures.
- Added pinned Windows and Ubuntu validation.

### Promotion status

- This source candidate is not a canary or stable promotion.
- Trusted promotion still requires the designated external authority and fixed external release-head provider.
- UX/accessibility remains `not_assessed`; source publication cannot make this candidate production-ready.
## 0.1.0 - 2026-07-15 - Private pilot candidate

### Added

- One plugin with exactly two visible skills: `build-with-design-system` and `audit-design-system`.
- Create-once immutable policy anchor and exact deny-first resolution contract.
- Isolated company profiles, DTCG token resolution, immutable catalog snapshots, source-cut vectors, and deterministic sentinels.
- Separate compliance and UX/accessibility audit lanes with incomplete-coverage blocking.
- Exact raw-visual-primitive diagnostic projection, direct local Git-metadata observation without ambient Git execution, and phase-local `snapshotUsable` / `pinCreated` lifecycle signals.
- Flutter-first analyzer adapter, host-owned analyzer runner, compilation-unit attestations, source/input hashing, exact sentinel evidence, and sealed analysis attestations.
- Deterministic migrations with pre-migration backups and append-only restoration records.
- Verifier-only Ed25519 release manifests, canary/stable local-ledger projections, full commit pinning, signed restoration actions, and a compile-time-blocked external/WORM head-provider protocol.

### Promotion status

- Not promoted by this changelog entry.
- A real canary or stable release still requires a future reviewed release that integrates the fixed external/WORM provider, the designated external authority, a signed manifest, the exact package artifact, and verification in the actual target Codex runtime.
- Version 0.1.0 has no trusted UX/accessibility evaluator. That lane remains `not_assessed` and exit `4`; this candidate cannot report production readiness until a reviewed host-attested evaluator is added.
