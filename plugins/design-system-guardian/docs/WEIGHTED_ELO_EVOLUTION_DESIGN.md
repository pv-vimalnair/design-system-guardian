# Weighted Elo and Permission-Gated Evolution

## Purpose

Design System Guardian must learn from completed runs without weakening its immutable design-system rule, leaking local company data, or changing itself without the user's permission. The feature remains internal infrastructure; the public package continues to expose exactly two skills.

## Non-negotiable boundaries

- The immutable policy digest and precedence remain unchanged. Evolution can never authorize an outside-system identity.
- Company profiles, snapshots, catalogs, and run evidence remain local under `~/.design-system-guardian/` and never enter the repository or release package.
- Public source contains only implementation, documentation, schemas, and synthetic benchmark fixtures.
- Guardian never records credentials, prompts, product source, raw tool output, general user activity, or local absolute paths in evolution or Elo evidence.
- A source outage, design-system gap, project violation, unsupported adapter, or incomplete assessment is not automatically a Guardian defect.
- Guardian proposes evolution and asks permission. It never edits, installs, commits, publishes, or updates itself before explicit approval.

## Post-run self-check

Every completed `finalize` operation creates one downstream, authority-sealed `post-run-assessment` beside the other profile-isolated run artifacts. The assessment references the sealed run manifest by digest and records only stable status codes, counts, and evidence digests.

It reports:

- what enforcement and evidence checks worked;
- what failed or remained unassessed;
- fixed reason codes and attribution (`project_implementation`, `design_system`, `source`, `project_configuration`, `capability_candidate`, or `plugin_candidate`);
- whether Plugin Evolution Manager review is useful;
- that evolution permission is required and no source mutation occurred.

One observed plugin-like failure remains a candidate. Only a deterministic regression test, an explicit source contract, or two matching reproductions under the same relevant conditions may confirm attribution to Guardian. Private findings must become non-identifying synthetic regression cases before they can affect public source or Elo.

`guardian self-check --profile <id> --run-id <id>` reads the sealed assessment. Both existing skills run it after finalization, report the result, and ask permission before starting an evolution workflow.

## Permission-gated evolution

After permission, the preferred Codex workflow is:

1. Run Plugin Evolution Manager's read-only health audit against the canonical owned source.
2. Reproduce and confirm the candidate.
3. Research current primary sources only when the confirmed repair needs it.
4. Design and implement the smallest repair with a synthetic regression test.
5. Run targeted tests, the full plugin gates, the public-release privacy gate, and weighted Elo evaluation.
6. Present the update and request any separately required installation or publication authority.

Compatible non-Codex agents use the same sealed handoff and equivalent review workflow. Guardian does not depend on a background daemon or a Codex-only hook.

## Weighted Guardian Elo

Guardian Elo uses model `guardian-weighted-elo-v1` and ranges from `1` to `2000`.

- A new local ledger starts at `1`.
- `2000` is reserved for demonstrated perfection: complete mandatory benchmark coverage, no mistakes, no open confirmed issue, no `not_assessed` lane, unchanged immutable policy, clean privacy gates, and verified support on every claimed host.
- Normal real-world runs never change Elo directly.
- The previous accepted version and candidate must run the exact same public synthetic suite.
- No measurable difference changes Elo by `0`.
- A benchmark achievement earns points once; removing or weakening a previously accepted benchmark is forbidden.
- Negative scoring requires a Guardian-attributed failure reproduced twice under matching package, policy, suite, and runtime evidence. External, source, and project failures never lower Elo.

Per-evaluation category caps are:

| Category | Maximum absolute change |
| --- | ---: |
| Correctness | 80 |
| Reliability | 40 |
| Coverage and usefulness | 30 |
| Safety, privacy, and integrity | 30 |
| Portability, usability, and performance | 20 |

For each category:

```text
netWeight = candidatePassedWeight - baselinePassedWeight
categoryDelta = sign(netWeight) * roundHalfUp(categoryCap * abs(netWeight) / totalCategoryWeight)
```

The release delta is clamped to `-200..200`; the resulting Elo is clamped to `1..2000`. An unconfirmed regression blocks an increase but does not lower Elo.

The append-only Elo ledger lives outside company profiles at `~/.design-system-guardian/evolution/elo/history/`. It contains only plugin, policy, public-suite, public-result, version, commit, score, and chain digests. It never contains a profile ID, company identity, project path, prompt, or user activity.

## Clean public release

Every publication is built and inspected from committed Git bytes, never mutable working-tree or local Guardian state. The release gate:

- requires a clean worktree and full commit;
- allowlists public repository paths;
- rejects runtime-state paths, symlinks, submodules, private-key or credential shapes, absolute account paths, and runtime-shaped profile/snapshot/audit documents;
- scans reachable history for prohibited runtime data;
- when local Guardian profiles exist, compares exact local-file digests and high-confidence design-system identifiers without printing their values;
- fails before push if any local company or user data is detected.

CI repeats the repository and history checks after checkout. The local-data-aware pre-push check remains mandatory because CI runs only after upload.

## Acceptance criteria

- Finalization automatically seals a deterministic post-run assessment for exit outcomes `0` through `4`.
- Status attribution never mistakes a design-system, source, project, or unsupported condition for a confirmed plugin regression.
- Elo arithmetic, bounds, duplicate prevention, reproduction requirements, and append-only integrity are tested.
- No source mutation is permitted before user approval.
- Privacy checks prove the public tree, package, and reachable history contain no local Guardian data available on the machine.
- Core, Flutter adapter, schema, plugin, skill, manifest, cross-agent packaging, and privacy gates pass.
- Codex is reinstalled and verified; other claimed hosts are validated honestly according to their available runtimes.
