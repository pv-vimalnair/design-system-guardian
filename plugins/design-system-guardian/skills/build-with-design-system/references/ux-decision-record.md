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
- known design-system or accessibility gaps, never an unauthorized workaround;
- the separate expected design-system, UX/accessibility, and protected production authority lanes; clean caller-carried Figma/UX evidence is expected to remain `not_assessed` until protected host attestation.

Update the record only when product intent changes. Do not switch the pinned snapshot, hand-author a pass, or silently replace a blocked identity.
