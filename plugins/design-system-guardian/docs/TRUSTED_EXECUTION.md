# Trusted execution boundary

Design System Guardian 0.3.8 is a cross-agent public source release. Its local HMAC seals detect accidental corruption and cross-run replay, but they are not production authority against code running as the same operating-system account. An agent process that can read the local sealing key must never turn its own local evidence into a production approval.

## Four independent lanes

Guardian reports these independently:

1. design-system compliance;
2. Usage Rules compliance;
3. UX/accessibility quality;
4. protected production authority.

The built-in evaluator can derive violations and gaps from screen and final-flow observations, Figma read-back can expose unbound or conflicting identities, and the Flutter analyzer can expose code/catalog mismatches. These are diagnostic failure signals. Clean schema-v2 personal-local Figma or Flutter coverage and caller-carried UX evidence remain `not_assessed` until protected host attestation.

A local run may fail design-system or UX lanes from proven violations or gaps. In every clean caller-carried case, both lanes remain `not_assessed`. Protected production authority remains unavailable and `productionReady=false`; never flatten local consistency into a green badge.

## Personal task and Figma-file selection

The default personal-local route requires a fresh explicit library decision for every Guardian task and every target Figma file:

    guardian selection status --run-id <run-id>
    guardian selection preview --run-id <run-id> --input <discovery.json>
    guardian selection apply --input <permission-bound-selection.json>

Status and preview are zero-write. The user must mark every complete discovered published library candidate **Use** or **Do not use** before apply. At least one library must be selected, every unselected library is forbidden, and a prior choice never transfers to another task, client, project, run, duplicate, file identity, or file version.

The discovery input also carries `catalogReadback` from the existing Figma connection. Guardian requires one exact proof for every canonical token, component, and icon; binds token value/type/mode/metadata, component variants/properties, and Code Connect mappings; rejects duplicate locators and selected-version mismatches; and binds the read-back digest into permission and selection evidence. Its authority is explicitly `unprotected_caller_carried`: it establishes local catalog/read-back consistency, not independent Figma provenance or a company signature.

The resulting local HMAC seal binds exact evidence and prevents silent cross-run reuse while that evidence remains intact. It does not prove independent company approval, prevent a same-account process from bypassing Guardian, or make `productionReady=true`. Personal selection state stays local and never enters Git, public Elo fixtures, telemetry, or the plugin package.

Organizations may instead use the existing externally signed enterprise onboarding and catalog-authority route. Personal selection neither replaces nor weakens that authority, and enterprise profiles remain enterprise-bound unless the user explicitly starts a separate personal-local task flow.

## Preview-only usage rules

Usage-rule validation is a local read-only preview. It writes no Guardian or project state, is not consumed by audit or finalization in version 0.3.4, and always reports `productionReady=false`. Even a syntactically valid rule result cannot supply protected production authority.

## Permission-bound Safe Activation

Version 0.3.5 may activate the first two compilation-unit predicate pairs only after a zero-write preview and explicit permission for the exact candidate digest. Permission enables the evaluator; it does not approve rules. The complete catalog v2 and every activated rule require the selected profile's pinned external catalog-authority signature.

Activation adds sealed evidence to a parallel append-only rule namespace and leaves all v1 state unchanged. Once v2 evidence exists, its absence or integrity failure blocks protected rule work; an older runtime or v1 snapshot is never an automatic fallback. Other predicates and scopes remain `not_assessed` until v0.3.6.

## Exact-run judgment boundary

Version 0.3.7 can derive a complete local subjective judgment assessment from sealed evidence. Guardian explains every finding first and always preserves raw findings beside the effective judgment projection. Only selected conflicts in one exact run can receive an exception, with an optional reason and explicit permission.

    guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>
    guardian judgment apply --input <granted-bundle.json>
    guardian judgment status --profile <profile-id> --run-id <run-id>
    guardian judgment revoke --input <granted-revocation.json>

Preview and status are zero-write; apply and revoke append only to local decision history after separate permission. Every new screen or flow is reevaluated. No exception is reusable across a duplicate file, later run, changed source cut, or future version.

The exception can change only the effective judgment outcome. It never changes raw evidence, design-system compliance, Usage Rules, sentinels, stale or incomplete evidence, unsupported or not-assessed coverage, or protected production authority. On an unprotected host, productionReady remains false and raw-tool bypass cannot be prevented. Assessments, reasons, decisions, revocations, and company evidence stay local and never enter Git, Elo, or telemetry.

## Required production boundary

A production gate must run the pinned Guardian release in a protected host or CI identity that the product-building agent cannot modify or impersonate. That host must provide all of the following as one reviewed integration:

- a canonical absolute, integrity-pinned Guardian interpreter or signed standalone executable;
- the exact trusted Figma observation or governed Dart SDK/framework package closure required by the selected adapter;
- independently protected analysis, UX, and finalization attestations;
- a rollback-resistant catalog approval high-water checkpoint;
- the required external/WORM release-head provider; and
- a final authority decision bound to the exact policy, profile, snapshot, source cut, target, and evaluator evidence.

No environment variable, project-local executable, caller-supplied path, local JSON file, in-process object, or plugin-cache file may stand in for that host. The provider must be fixed by reviewed code and fail closed when unavailable.

## Diagnostic behavior

Version 0.3.8 does not integrate protected production authority. Local audit output is diagnostic: violations and gaps can fail, while clean schema-v2 personal-local Figma or Flutter coverage and caller-carried UX evidence remain `not_assessed`. None of these local results supplies protected authority; `productionReady=false` whenever protected attestation is unavailable.

The convenience launchers `scripts/guardian` and `scripts/guardian.cmd` deliberately exit `4`; they do not discover Python from `PATH`. A protected host invokes `scripts/guardian.py` through its authority-bound runtime. For diagnostics and repository tests, a host-supplied absolute Python executable may invoke it after its path and SHA-256 are recorded. That route cannot change the protected lane.

Skill portability does not create an always-on protected route, and Guardian cannot prevent raw-tool bypass on an unprotected host. No sealed Guardian manifest means the work is not Guardian-approved. A sealed diagnostic manifest still does not claim protected production authority unless the protected lane says so explicitly.
