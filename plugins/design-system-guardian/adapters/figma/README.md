# Guardian Figma adapter

This adapter is a strict, local, read-only evidence boundary. It does not add a
second Figma integration, request credentials, or write to a Figma file. The
host agent runs the shipped collector through its existing Figma plugin/MCP
connection and gives the result to Guardian for deterministic normalization.

## Host flow

1. Verify the policy anchor, selected profile, run pin, and complete snapshot.
2. Call `build_figma_adapter_config(...)`. By default it binds the config to
   `collector_digest()`, the stable digest of collector contract v1, the exact
   run ID, and the preflight project-binding digest.
3. Through the host's existing Figma connection, execute
   `GuardianFigmaCollector.collectGuardianFigmaObservation(config, context)` in
   the open file. No Figma credential is passed to Guardian.
4. Save the returned observation as local run evidence and call
   `normalize_figma_observation(...)` with the same run pin and verified
   snapshot.
5. Call `expected_figma_ux_target(...)` with that same observation, run pin,
   and snapshot. A v2 UX evaluation must use the returned target exactly.
6. Feed the normalized result and matching UX evaluation into the normal
   Guardian audit/finalize path.

The expected UX target cannot be supplied or guessed by the caller. Its screen
digests are derived from the exact Figma file key, pinned source version, and
sorted root node IDs; its flow digest also binds those screens to the run ID,
project-binding digest, and adapter-config digest. Reusing an evaluation from
another run, project, document version, or selected root therefore cannot
match.

The context is intentionally small:

```json
{
  "source": {
    "state": "fresh",
    "available": true,
    "complete": true
  },
  "document": {
    "fileKey": "working-file-key",
    "sourceVersion": "exact-pinned-version",
    "rootNodeIds": ["0:1"]
  }
}
```

`sourceVersion` must come from the already connected source adapter or REST/MCP
snapshot. The collector never guesses a version from a file name or visual
content. A mismatch with the source cut is `stale`; unreadable or insufficient
source evidence is `source_unavailable` or `source_incomplete`. None of those
states is converted to `missing`.

### Portable authority boundary

The portable host has no protected receipt proving that the shipped
collector executable produced caller-carried JSON. Therefore exact run and
project bindings prevent replay, and exact violations remain actionable
diagnostics, but clean Figma categories are deliberately `not_assessed`. They
cannot become an `allowed` coverage or production claim. A future protected
host may promote clean coverage only after verifying a collector execution
receipt that is outside caller control.

## What counts as proof

- Variable use requires an actual `boundVariables` alias resolved to the exact
  stable variable key, collection key, and resolved type in the snapshot.
- Style use requires the applied style ID to resolve to the exact stable style
  key and style type in the snapshot. Mixed text is checked range by range.
- Component/icon use requires an instance whose main component key, remote/local
  state, variant, properties, overrides, file key, node ID, and source version
  satisfy the exact approved evidence.
- Component properties retain only approved visual variant/property values.
  Figma `TEXT` property values and raw text-node characters are never collected;
  unapproved non-text property names can fail closed without retaining values.
- A raw value is always a violation. Its value is retained only as a local
  SHA-256 digest. `inferredVariables` may explain an equal-looking match but can
  never turn it into an approved binding.
- Any unassessed field keeps its audit lane `not_assessed`; incomplete coverage
  cannot become a production pass.

The collector does not treat matching names, equal colors, copied values,
framework defaults, local recreation, or detached frames as approval. A default
white frame is therefore visible as an unbound fill instead of silently looking
"on system."

## Duplicate and working Figma files

Guardian reuses the snapshot's `workingFileInstances` lineage evidence. When a
working or duplicate file is pinned, the collector reads the real node and the
normalizer compares the complete instance record with the signed record. A
detached frame, local copy, look-alike component key, changed property, changed
variant, override, or version drift fails exact comparison.

There is no separate manual duplicate-file allowlist in this adapter. Discovery
and reconciliation establish lineage; this read-back boundary only verifies it.
If lineage is absent or ambiguous, the affected asset cannot pass.

## Compatibility contract

Python hosts may omit the optional `collector_digest` argument; Guardian uses
the shipped digest. A supplied digest is accepted only when it equals
`collector_digest()`. This verifies contract compatibility while keeping the
digest stable across line-ending or packaging changes; it is not a protected
execution receipt. Any semantic collector change must update the stable
contract payload and, after release, its contract/adapter versions.

The JavaScript file works as either:

- `globalThis.GuardianFigmaCollector` inside a Figma plugin runtime; or
- a CommonJS import for a host wrapper/test harness.

The implementation uses only read APIs, including `boundVariables`,
`getStyleByIdAsync`, and `getMainComponentAsync`. It does not create nodes,
change layout, bind variables, apply styles, use network access, or inspect
credentials. This also avoids the creation-time plugin API traps around default
frame fills, layout-only sizing modes, and variant instantiation.

## Local-data boundary

The config, observation, manifests, and audit records remain local to the user's
Guardian data directory. Raw visual values are digested before they enter the
observation, while ordinary text-node and component-copy content is neither
retained nor hashed. The public plugin
contains only this generic collector, schema, and validator; it contains no
company profile, catalog, Figma file key, component identity, or usage history.
