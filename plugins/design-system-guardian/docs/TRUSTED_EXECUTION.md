# Trusted execution boundary

Design System Guardian 0.3.3 is a cross-agent public source release. Its local HMAC seals detect accidental corruption and cross-run replay, but they are not production authority against code running as the same operating-system account. An agent process that can read the local sealing key must never turn its own local evidence into a production approval.

## Three independent lanes

Guardian reports these independently:

1. design-system compliance;
2. UX/accessibility quality;
3. protected production authority.

The built-in evaluator can derive violations and gaps from screen and final-flow observations, and Figma read-back can expose unbound or conflicting identities. These are diagnostic failure signals. Clean caller-carried Figma or UX evidence remains `not_assessed` until protected host attestation; neither local mechanism can issue `allowed`.

A local run may fail design-system or UX lanes from proven violations or gaps. In the clean case it must report those caller-carried lanes as `not_assessed`, protected authority as unavailable, and `productionReady=false`. Never flatten diagnostic evidence into a green badge.

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

Version 0.3.3 does not integrate protected production authority. Local audit output is diagnostic: violations and gaps can fail, but a clean Figma or UX observation remains `not_assessed` rather than passing. `productionReady=false` whenever protected attestation is unavailable.

The convenience launchers `scripts/guardian` and `scripts/guardian.cmd` deliberately exit `4`; they do not discover Python from `PATH`. A protected host invokes `scripts/guardian.py` through its authority-bound runtime. For diagnostics and repository tests, a host-supplied absolute Python executable may invoke it after its path and SHA-256 are recorded. That route cannot change the protected lane.

Skill portability does not create an always-on protected route, and Guardian cannot prevent raw-tool bypass on an unprotected host. No sealed Guardian manifest means the work is not Guardian-approved. A sealed diagnostic manifest still does not claim protected production authority unless the protected lane says so explicitly.
