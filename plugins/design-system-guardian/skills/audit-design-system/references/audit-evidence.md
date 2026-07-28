# Audit evidence checklist

Before accepting final audit evidence, verify:

- one explicit profile and no cross-profile identities;
- immutable policy digest and pinned catalog-authority key verified;
- setup permission, when required, bound to the exact local profile/Figma allowlist/catalog digests;
- one pinned snapshot and source-cut vector for the full audit;
- exact source freshness at finalization time;
- all eight design-system categories contain assessed and total counts;
- selected adapter, policy, profile, snapshot, source cut, and generated config all match; the Figma config stays inside Guardian local state and outside product/Git paths;
- Figma evidence comes from the fixed collector and proves exact bound variables, text styles/ranges, instances, component keys, variants/properties, source versions, and approved duplicate lineage;
- Flutter evidence comes from Guardian-owned analyzer execution and proves source/toolchain/package coverage;
- raw values, sampled values, framework defaults, unapproved variants, wrappers, and suppressions are diagnostics;
- each resolution is canonical, ordered, and bound to the run;
- every `allowed` result selects the exact requested identity;
- every `missing` result has the fixed sentinel; no other status has one;
- quick screen checkpoints are marked diagnostic and not used as final authority;
- final-flow UX evidence rechecks every selected screen and all required flow areas;
- every active judgment rule has a complete raw assessment or remains not_assessed;
- exact-run decisions identify only selected conflict findings, preserve every raw finding, and show raw and effective results separately;
- current status proves whether each exact-run approval remains active or has an append-only revocation;
- UX failures are evaluator-derived and not caller-authored; clean caller-carried Figma and UX evidence remains `not_assessed` until protected host attestation, including exact version 2 personal-local read-back;
- design-system, UX/accessibility, and protected production authority lanes remain separate;
- inaccessible approved assets are design-system gaps, not substituted fixes;
- `not_assessed`, `unsupported`, incomplete, stale, or unavailable evidence never becomes a pass;
- portable skill installation is not automatic routing and cannot prevent raw-tool bypass without an always-on protected route; no sealed Guardian manifest means not Guardian-approved;
- local company/profile/catalog/Figma/run data is absent from public release content;
- judgment assessments, optional reasons, decisions, revocations, and company evidence never enter Git, Elo, or telemetry;
- no exact-run exception is reused for a new screen, flow, run, version, or duplicate file.

Readable reports are projections only. Treat sealed canonical JSON and verified digests as authoritative.
