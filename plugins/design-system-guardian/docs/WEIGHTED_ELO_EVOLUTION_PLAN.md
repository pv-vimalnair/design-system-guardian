# Weighted Elo and Permission-Gated Evolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic local post-run self-checks, permission-gated evolution handoff, weighted Guardian Elo, and a deterministic clean-public-release privacy gate without adding another visible skill.

**Architecture:** `finalize` derives one profile-isolated sealed assessment from already verified run evidence. A separate global append-only Elo ledger accepts only public synthetic benchmark comparisons, while a standard-library release checker inspects committed bytes and local Guardian identifiers before publication.

**Tech Stack:** Python 3.11+, canonical JSON, existing Guardian authority seals and storage helpers, `unittest`, JSON Schema 2020-12, Git, Agent Skills manifests.

## Global Constraints

- Preserve immutable policy digest `3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f`.
- Keep exactly `build-with-design-system` and `audit-design-system` as visible skills.
- Keep all company design-system and run data under `~/.design-system-guardian/`; publish none of it.
- Start Guardian Elo at `1`, cap it at `2000`, and cap one evaluation at `200` absolute points using weights `80/40/30/30/20`.
- Require confirmed same-condition Guardian attribution before a negative Elo change.
- Do not add a dependency, background service, telemetry endpoint, credential store, or another plugin.

---

### Task 1: Post-run assessment contract

**Files:**
- Create: `guardian_core/post_run.py`
- Create: `schemas/post-run-assessment.schema.json`
- Modify: `guardian_core/run_artifacts.py`
- Modify: `schemas/lifecycle/sealed-run-artifact.schema.json`
- Test: `tests/test_post_run_assessment.py`

**Interfaces:**
- Consumes: verified audit result, run manifest, artifact digests, runtime version.
- Produces: `build_post_run_assessment(...) -> dict[str, Any]` and sealed artifact type `post-run-assessment`.

- [ ] **Step 1: Write failing assessment tests**

```python
assessment = build_post_run_assessment(
    audit_result=audit,
    run_manifest=manifest,
    run_manifest_digest="a" * 64,
    runtime_version="0.3.0",
)
self.assertEqual(assessment["evolutionHandoff"]["status"], "permission_required")
self.assertNotIn("message", canonical_json_text(assessment))
```

- [ ] **Step 2: Run the focused tests and confirm failure**

```powershell
python -m unittest tests.test_post_run_assessment -v
```

Expected: import or missing-artifact failure before implementation.

- [ ] **Step 3: Implement deterministic attribution and strict fields**

```python
ALLOWED_ATTRIBUTIONS = {
    "project_implementation", "design_system", "source",
    "project_configuration", "capability_candidate", "plugin_candidate",
}
```

Derive counts and reason codes only. Never copy diagnostic messages, product paths, catalog payloads, prompts, or raw output.

- [ ] **Step 4: Add the strict schema and artifact enum**

Require exact identity/digest/status/count/handoff fields and reject additional properties. Add both runtime-supported `analysis-attestation` and `post-run-assessment` to the lifecycle envelope enum.

- [ ] **Step 5: Run focused tests**

```powershell
python -m unittest tests.test_post_run_assessment tests.test_lifecycle_schemas_dsg003 -v
```

Expected: pass.

### Task 2: Automatic finalization and portable self-check

**Files:**
- Modify: `guardian_core/finalize.py`
- Modify: `guardian_core/cli.py`
- Modify: `tests/test_finalize_artifacts_dsg003.py`
- Modify: `tests/test_cli_lifecycle_dsg003.py`
- Modify: `skills/build-with-design-system/SKILL.md`
- Modify: `skills/audit-design-system/SKILL.md`

**Interfaces:**
- Consumes: sealed final audit and manifest evidence.
- Produces: automatic `post-run-assessment`, `guardian self-check --profile --run-id`, and permission-required handoff.

- [ ] **Step 1: Add failing finalize and CLI assertions**

```python
self.assertIn("post-run-assessment", result.artifact_paths)
self.assertEqual(result.post_run_assessment["sourceMutationPerformed"], False)
```

- [ ] **Step 2: Seal the assessment after the run manifest**

Bind `runManifestDigest` downstream of the manifest to avoid a digest cycle. Preserve idempotent create-once behavior.

- [ ] **Step 3: Add read-only CLI output**

```text
guardian self-check --profile <profile> --run-id <run>
```

Read and verify the sealed artifact; do not accept caller-authored assessment content.

- [ ] **Step 4: Update both skills**

Require self-check after finalization, report worked/failed/reason codes, ask permission, and only then use Plugin Evolution Manager or an equivalent portable workflow. Keep audit read-only for the audited product.

- [ ] **Step 5: Run focused tests and skill validators**

Expected: assessment generated, returned, readable, and exactly two skills remain.

### Task 3: Weighted Elo ledger and benchmark comparison

**Files:**
- Create: `guardian_core/elo.py`
- Create: `schemas/evolution/elo-benchmark-result.schema.json`
- Create: `schemas/evolution/elo-ledger-entry.schema.json`
- Create: `benchmarks/elo-suite.json`
- Create: `benchmarks/current-score.json`
- Modify: `guardian_core/paths.py`
- Modify: `guardian_core/cli.py`
- Test: `tests/test_weighted_elo.py`

**Interfaces:**
- Produces: `read_elo_state(home)`, `evaluate_elo(home, baseline, candidate)`, `guardian elo show`, and `guardian elo evaluate`.

- [ ] **Step 1: Write failing arithmetic and integrity tests**

```python
self.assertEqual(ELO_WEIGHTS, {
    "correctness": 80, "reliability": 40, "coverage": 30,
    "safety_privacy": 30, "portability_performance": 20,
})
self.assertEqual(read_elo_state(home)["score"], 1)
```

Cover zero change, positive change, confirmed double-reproduction regression, external failure, duplicate achievement, `+/-200` cap, `1..2000` bounds, and ledger tampering.

- [ ] **Step 2: Implement exact comparison math**

Use integer half-up rounding, exact suite/policy/runtime digests, one-time benchmark achievement IDs, and no free-form private fields.

- [ ] **Step 3: Implement create-once chained events**

Store events at `~/.design-system-guardian/evolution/elo/history/<sequence>-<digest>.sealed.json`. Verify the full chain before reading or appending.

- [ ] **Step 4: Add CLI and public synthetic baseline**

`elo show` returns `1` on a new installation. `elo evaluate` requires canonical public benchmark results and never reads a company profile.

- [ ] **Step 5: Run focused tests and schema validation**

Expected: all Elo tests pass and local/company identifiers are rejected from ledger evidence.

### Task 4: Clean-public-release gate

**Files:**
- Create: `scripts/check_public_release.py`
- Replace: `tests/test_publication_privacy_dsg014.py`
- Modify: `.github/workflows/validate.yml`
- Modify: repository `.gitignore`
- Modify: `SECURITY.md`
- Modify: `docs/UPDATING.md`

**Interfaces:**
- Produces: a zero-data public-tree result from committed Git bytes; nonzero on runtime/private evidence.

- [ ] **Step 1: Write synthetic failing privacy tests**

Test runtime paths, absolute homes, runtime-shaped JSON, private identifier and exact-file matches, symlinks/submodules, dirty trees, reachable history, and redacted output.

- [ ] **Step 2: Implement the standard-library checker**

Use `git ls-tree`/`git cat-file` against a full commit and a strict public-path allowlist. With local profiles present, extract only high-confidence identifiers for comparison and never print values.

- [ ] **Step 3: Wire CI and documentation**

Run structural/history mode immediately after checkout. Document the local-data-aware check as mandatory before push.

- [ ] **Step 4: Run focused privacy tests and the real local check**

```powershell
python scripts/check_public_release.py --repository-root <repo> --history
```

Expected: pass with a clean commit and no local-data matches.

### Task 5: Cross-agent release and verification

**Files:**
- Modify: Codex, Claude Code, Claude marketplace, Kimi, Flutter, runtime, README, changelog, and version assertion files.
- Modify: generic installer package entries only if the new public benchmark directory is not already covered.

- [ ] **Step 1: Synchronize strict SemVer `0.3.0`**

Keep every host manifest and `guardian_core.release.RUNTIME_VERSION` equal.

- [ ] **Step 2: Run targeted and complete gates**

Run core and Flutter suites, schema parsing, Python compilation, plugin validator, both skill validators, Claude manifest validators, cross-agent package tests, privacy/history scan, and `git diff --check`.

- [ ] **Step 3: Independently review scope and privacy**

Require no policy change, exactly two skills, no company/user data, and no unsupported host claim.

- [ ] **Step 4: Commit and push publicly**

Commit one logical feature, rerun the clean committed-tree privacy check, push to public `main`, and verify GitHub Actions on Windows and Ubuntu.

- [ ] **Step 5: Reinstall and verify live surfaces**

Use the plugin-creator cachebuster/reinstall flow for Codex. Verify the installed cache version, immutable policy digest, two-skill surface, CLI help, self-check/Elo help, and generic installer binding. Report unavailable native host runtimes as unverified rather than passed.
