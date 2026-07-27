# UX decision record

Create this record before changing product UI and bind it to one Guardian run.

Required fields:

- `runId`, `profileId`, policy digest, snapshot ID, and source-cut digest;
- setup status and, when onboarding occurred, the exact permission-binding digest (never copy the private candidate);
- selected adapter (`figma` or `flutter`) and generated adapter-config digest; the Figma config path must remain inside canonical Guardian local state, never the product or Git tree;
- user goal, primary task, information hierarchy, and component intent;
- normal, empty, loading, error, disabled, success, and permission states as applicable;
- keyboard, focus, screen-reader, contrast, reduced-motion, and touch-target considerations;
- one exact planned identity and resolution request for every component, icon, color, typography, spacing, radius, effect, and motion choice;
- for Figma, the planned variable/text-style bindings, component key, variant/properties, and approved duplicate locator when applicable;
- normal product copy with its approved text component and presentation identities;
- each quick screen checkpoint target/evidence digest and the final-flow target/evidence digest;
- the complete v0.3.7 judgment assessment digest, every raw finding, and the derived effective result;
- any selected exact-run conflict exception, its optional reason, decision digest, and current revocation status;
- known design-system or accessibility gaps, never an unauthorized workaround;
- the separate expected design-system, UX/accessibility, and protected production authority lanes; clean caller-carried Figma/UX evidence is expected to remain `not_assessed` until protected host attestation.

Update product-intent content only when product intent changes. Reevaluate every new screen or flow; never copy an exception to a duplicate file, later run, or future version. Do not switch the pinned snapshot, hand-author a pass, or silently replace a blocked identity.

Refresh the judgment assessment, selected decision, derived effective result, and current revocation status from the canonical `guardian judgment status --profile <profile-id> --run-id <run-id>` read-back whenever canonical judgment state changes, including apply or revoke. Never leave cached judgment status in the record.

Assessments, reasons, decisions, and company evidence stay in Guardian local state and never enter the product, Git, Elo, or telemetry.
