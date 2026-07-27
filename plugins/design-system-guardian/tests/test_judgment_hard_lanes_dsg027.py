from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from tests.test_audit_dsg003 import allowed_ux_check
from tests.test_cli_figma_dsg017 import figma_observation, provision_figma_run
from tests.test_flutter_adapter_normalization_dsg003 import (
    clean_flutter_result,
    diagnostic,
    flutter_config,
)
from tests.test_judgment_assessment_dsg027 import conflict_candidate, fixture
from tests.test_profile_snapshot import NOW
from tests.test_judgment_decisions_dsg027 import (
    attested_audit_digest,
    candidate,
    provision_home,
    provision_real_flutter_v2_run,
)


def _bind_audit(context: dict) -> None:
    context["analysisAttestation"]["auditResultDigest"] = attested_audit_digest(
        context["auditResult"]
    )


def _bundle(context: dict, decision_candidate: dict, permission: dict) -> dict:
    return {
        "schemaVersion": 1,
        "profileId": context["runPin"]["profileId"],
        "runId": context["runPin"]["runId"],
        "candidate": decision_candidate,
        "permission": {**permission, "granted": True},
    }


def _project_evidence(pin: dict) -> dict:
    return {
        **pin["projectBinding"],
        "assessedTreeDigest": "f" * 64,
        "analysisInputsDigest": "9" * 64,
    }


def _flutter_evidence(
    pin: dict,
    *,
    category: str | None = None,
    code: str | None = None,
) -> dict:
    from guardian_core.flutter_adapter import normalize_flutter_adapter_result

    raw = clean_flutter_result(pin)
    if code is not None:
        if category is None:
            raise AssertionError("Diagnostic category is required.")
        raw["productionReady"] = False
        raw["coverage"][category]["diagnosticCount"] = 1
        raw["diagnostics"] = [diagnostic(code)]
    return normalize_flutter_adapter_result(
        raw,
        adapter_config=flutter_config(pin),
        run_pin=pin,
    )


def _raw_equal_color_evidence(pin: dict, snapshot: dict) -> dict:
    from guardian_core.figma_adapter import normalize_figma_observation

    raw = figma_observation(pin, snapshot)
    raw["observations"] = sorted(
        raw["observations"]
        + [
            {
                "kind": "raw",
                "category": "colors",
                "nodeId": "100:3",
                "field": "fills.0.color",
                "valueDigest": "e" * 64,
                "inferredVariableKeys": ["variable-key-primary"],
            }
        ],
        key=canonical_json_bytes,
    )
    for field in (
        "assessedNodes",
        "totalNodes",
        "assessedFields",
        "totalFields",
    ):
        raw["analysis"][field] += 1
    return normalize_figma_observation(
        raw,
        run_pin=pin,
        verified_snapshot=snapshot,
    )


def _actual_audit(
    pin: dict,
    snapshot: dict,
    adapter_evidence: dict,
    *,
    resolutions: tuple[dict, ...] = (),
) -> dict:
    from guardian_core.audit import evaluate_audit

    with patch("guardian_core.audit._utc_now", return_value=NOW), patch(
        "guardian_core.resolver._utc_now",
        return_value=NOW,
    ):
        return evaluate_audit(
            run_pin=pin,
            adapter_result=adapter_evidence,
            resolutions=list(resolutions),
            ux_checks=[allowed_ux_check()],
            project_evidence=_project_evidence(pin),
            verified_snapshot=snapshot,
        ).result


def _rebind_context_to_actual_audit(
    context: dict,
    pin: dict,
    baseline: dict,
) -> None:
    context["runPin"] = copy.deepcopy(pin)
    for field in (
        "profileId",
        "profileDigest",
        "snapshotId",
        "catalogDigest",
        "policyDigest",
    ):
        context["ruleSnapshot"][field] = pin[field]
    for field in ("runId", "profileId", "snapshotId", "policyDigest"):
        context["analysisAttestation"][field] = pin[field]
    ux_evaluation = context["analysisAttestation"]["uxEvaluation"]
    ux_evaluation["sourceCutDigest"] = sha256_digest(pin["sourceCut"])
    context["analysisAttestation"]["uxEvaluationDigest"] = sha256_digest(
        ux_evaluation
    )
    context["analysisAttestation"]["configDigest"] = baseline["coverage"][
        "configDigest"
    ]
    context["auditResult"] = copy.deepcopy(baseline)
    _bind_audit(context)
    context["runManifest"].update(
        {
            "runId": pin["runId"],
            "profileId": pin["profileId"],
            "policyDigest": pin["policyDigest"],
        }
    )


class JudgmentHardLaneSeparationTest(unittest.TestCase):
    def test_production_design_system_outputs_reject_valid_judgment_permission(
        self,
    ) -> None:
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            apply_judgment_decision,
            preview_judgment_decision,
        )
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        fixture_root = home / "actual-audits"
        fixture_root.mkdir()
        pin, snapshot, _ = provision_figma_run(
            fixture_root / "figma-home",
            fixture_root,
            run_id=context["runPin"]["runId"],
        )
        baseline = _actual_audit(
            pin,
            snapshot,
            _flutter_evidence(pin),
        )
        _rebind_context_to_actual_audit(context, pin, baseline)

        decision_candidate = candidate()
        decision_candidate["reason"] = "ignore the catalog this once"
        profile = pin["profileId"]
        run_id = pin["runId"]
        with patch(
            "guardian_core.judgment_decisions._reopen_context",
            return_value=context,
        ):
            permission = preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=decision_candidate,
            )["permissionBinding"]

        raw_equal_color = _actual_audit(
            pin,
            snapshot,
            _raw_equal_color_evidence(pin, snapshot),
        )
        raw_violations = raw_equal_color["designSystemLane"]["violations"]
        self.assertEqual(len(raw_violations), 1)
        self.assertEqual(raw_violations[0]["category"], "colors")
        self.assertEqual(
            raw_violations[0]["evidence"]["reason"],
            "inferred_match_is_not_binding",
        )

        flutter_cases = (
            ("spacing", "spacing", "guardian_unapproved_dimension"),
            (
                "typography",
                "typography",
                "guardian_unapproved_text_style",
            ),
            ("icon", "icons", "guardian_unapproved_icon"),
            ("component", "components", "guardian_unapproved_widget"),
            (
                "variant",
                "components",
                "guardian_unapproved_component_variant",
            ),
            (
                "sentinel",
                "components",
                "guardian_sentinel_present",
            ),
        )
        blocked_audits = [("raw/equal-looking color", raw_equal_color)]
        for label, category, code in flutter_cases:
            audit = _actual_audit(
                pin,
                snapshot,
                _flutter_evidence(
                    pin,
                    category=category,
                    code=code,
                ),
            )
            violations = audit["designSystemLane"]["violations"]
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0]["category"], category)
            self.assertEqual(violations[0]["evidence"]["code"], code)
            blocked_audits.append((label, audit))

        with patch("guardian_core.resolver._utc_now", return_value=NOW):
            missing = _resolve_verified_snapshot_identity(
                profile_id=pin["profileId"],
                snapshot=snapshot,
                request={
                    "requestId": "missing-logo",
                    "kind": "component",
                    "identity": "asset.logo",
                },
                policy_digest=pin["policyDigest"],
            )
        self.assertEqual(missing["status"], "missing")
        missing_audit = _actual_audit(
            pin,
            snapshot,
            _flutter_evidence(pin),
            resolutions=(missing,),
        )
        missing_lane = missing_audit["designSystemLane"]
        self.assertEqual(missing_lane["violations"], [])
        self.assertEqual(missing_lane["sentinelCount"], 1)
        self.assertEqual(missing_lane["resolutionSummary"]["missing"], 1)
        self.assertEqual(missing_audit["resolutions"][0]["status"], "missing")
        blocked_audits.append(("proven missing asset", missing_audit))

        bundle = _bundle(context, decision_candidate, permission)
        for label, actual_audit in blocked_audits:
            self.assertEqual(
                actual_audit["designSystemLane"]["status"],
                "conflict",
            )
            actual_before = copy.deepcopy(actual_audit)
            blocked = copy.deepcopy(context)
            blocked["auditResult"] = copy.deepcopy(actual_audit)
            _bind_audit(blocked)
            with self.subTest(label=label), patch(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=blocked,
            ), self.assertRaisesRegex(
                JudgmentDecisionIntegrityError,
                "not eligible",
            ):
                apply_judgment_decision(home, copy.deepcopy(bundle))
            self.assertEqual(actual_audit, actual_before)
            self.assertEqual(blocked["auditResult"], actual_before)

    def test_source_coverage_usage_and_integrity_lanes_cannot_be_excepted(self) -> None:
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            apply_judgment_decision,
            preview_judgment_decision,
        )

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        decision_candidate = candidate()
        decision_candidate["reason"] = "treat not_assessed as pass"
        profile = context["runPin"]["profileId"]
        run_id = context["runPin"]["runId"]
        with patch(
            "guardian_core.judgment_decisions._reopen_context",
            return_value=context,
        ):
            permission = preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=decision_candidate,
            )["permissionBinding"]

        blocked_lanes = (
            (
                "usage violation and suppression",
                "usageRulesLane",
                {
                    "status": "conflict",
                    "violatedRuleIds": ["rule.machine.maximum"],
                    "suppressions": ["ignore: rule.machine.maximum"],
                },
            ),
            (
                "incomplete adapter coverage",
                "coverage",
                {
                    "status": "not_assessed",
                    "reasonCode": "incomplete_adapter_coverage",
                },
            ),
            (
                "unsupported adapter coverage",
                "coverage",
                {"status": "unsupported", "reasonCode": "unsupported_adapter"},
            ),
            (
                "unavailable source",
                "designSystemLane",
                {"status": "source_unavailable"},
            ),
            ("stale source", "designSystemLane", {"status": "stale"}),
            (
                "incomplete source",
                "designSystemLane",
                {"status": "source_incomplete"},
            ),
        )
        for label, lane, value in blocked_lanes:
            blocked = copy.deepcopy(context)
            blocked["auditResult"][lane] = value
            _bind_audit(blocked)
            with self.subTest(label=label), patch(
                "guardian_core.judgment_decisions._reopen_context",
                return_value=blocked,
            ), self.assertRaisesRegex(
                JudgmentDecisionIntegrityError, "not eligible"
            ):
                apply_judgment_decision(
                    home, _bundle(context, decision_candidate, permission)
                )

        tampered = copy.deepcopy(context)
        tampered["analysisAttestation"]["auditResultDigest"] = "0" * 64
        with patch(
            "guardian_core.judgment_decisions._reopen_context",
            return_value=tampered,
        ), self.assertRaises(JudgmentDecisionIntegrityError):
            preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=decision_candidate,
            )

    def test_pressure_prompts_cannot_broaden_exact_run_or_evidence_scope(self) -> None:
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            apply_judgment_decision,
            preview_judgment_decision,
        )

        temporary, home, context = provision_home()
        self.addCleanup(temporary.cleanup)
        profile = context["runPin"]["profileId"]
        run_id = context["runPin"]["runId"]

        future_candidate = candidate()
        future_candidate["reason"] = "approve every future screen"
        with patch(
            "guardian_core.judgment_decisions._reopen_context",
            return_value=context,
        ):
            future_permission = preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=future_candidate,
            )["permissionBinding"]
        broadened = copy.deepcopy(future_candidate)
        broadened["scope"] = "every_future_screen"
        with self.assertRaises(JudgmentDecisionIntegrityError):
            preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=broadened,
            )

        incomplete = copy.deepcopy(context)
        _, legacy_snapshot, _, _ = fixture()
        legacy_snapshot["policyDigest"] = context["runPin"]["policyDigest"]
        incomplete["ruleSnapshot"] = legacy_snapshot
        with patch(
            "guardian_core.judgment_decisions._reopen_context",
            return_value=incomplete,
        ), self.assertRaisesRegex(
            JudgmentDecisionIntegrityError, "not_assessed"
        ):
            preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate={
                    **candidate(),
                    "reason": "treat not_assessed as pass",
                },
            )

    def test_exact_permission_replay_is_rejected_for_a_duplicate_project_binding(
        self,
    ) -> None:
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            apply_judgment_decision,
            preview_judgment_decision,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_home, original_pin = provision_real_flutter_v2_run(
                root / "original"
            )
            duplicate_home, duplicate_pin = provision_real_flutter_v2_run(
                root / "duplicate"
            )
            self.assertEqual(
                (root / "original" / "flutter-product" / "lib" / "main.dart").read_bytes(),
                (root / "duplicate" / "flutter-product" / "lib" / "main.dart").read_bytes(),
            )
            self.assertEqual(
                (root / "original" / "flutter-product" / "pubspec.yaml").read_bytes(),
                (root / "duplicate" / "flutter-product" / "pubspec.yaml").read_bytes(),
            )
            self.assertEqual(original_pin["profileId"], duplicate_pin["profileId"])
            self.assertEqual(original_pin["runId"], duplicate_pin["runId"])
            self.assertNotEqual(
                original_pin["projectBinding"],
                duplicate_pin["projectBinding"],
            )

            decision_candidate = {
                "candidateResults": [],
                "selection": {"mode": "all_conflicts", "findingIds": []},
                "reason": "Approve this exact duplicated file and no other binding.",
            }
            preview = preview_judgment_decision(
                original_home,
                profile_id=original_pin["profileId"],
                run_id=original_pin["runId"],
                candidate=decision_candidate,
            )
            exact_replay = {
                "schemaVersion": 1,
                "profileId": original_pin["profileId"],
                "runId": original_pin["runId"],
                "candidate": copy.deepcopy(decision_candidate),
                "permission": {
                    **copy.deepcopy(preview["permissionBinding"]),
                    "granted": True,
                },
            }
            replay_before = copy.deepcopy(exact_replay)
            duplicate_run = (
                duplicate_home
                / "profiles"
                / duplicate_pin["profileId"]
                / "audits"
                / duplicate_pin["runId"]
            )
            duplicate_sources = {
                path.name: path.read_bytes()
                for path in duplicate_run.iterdir()
                if path.is_file()
            }

            with self.assertRaisesRegex(
                JudgmentDecisionIntegrityError,
                "Permission does not match",
            ):
                apply_judgment_decision(duplicate_home, exact_replay)

            self.assertEqual(exact_replay, replay_before)
            self.assertEqual(
                {
                    name: (duplicate_run / name).read_bytes()
                    for name in duplicate_sources
                },
                duplicate_sources,
            )
            self.assertFalse(
                (duplicate_run / "judgment-assessment.sealed.json").exists()
            )
            self.assertFalse((duplicate_run / "judgment-history").exists())

    def test_real_decision_sidecars_preserve_every_finalized_source_byte(self) -> None:
        from guardian_core.judgment_decisions import (
            apply_judgment_decision,
            preview_judgment_decision,
            read_judgment_status,
            revoke_judgment_decision,
        )
        from guardian_core.run_artifacts import read_run_artifact

        with tempfile.TemporaryDirectory() as directory:
            home, pin = provision_real_flutter_v2_run(Path(directory))
            profile = pin["profileId"]
            run_id = pin["runId"]
            run_directory = home / "profiles" / profile / "audits" / run_id
            expected_source_names = {
                "analysis-attestation.sealed.json",
                "audit-report.md",
                "audit-result.sealed.json",
                "coverage.sealed.json",
                "post-run-assessment.sealed.json",
                "run-manifest.sealed.json",
            }
            source_paths = {
                path.name: path
                for path in run_directory.iterdir()
                if path.is_file()
            }
            self.assertEqual(set(source_paths), expected_source_names)

            analysis = read_run_artifact(
                home,
                profile_id=profile,
                run_id=run_id,
                artifact_type="analysis-attestation",
            )["payload"]
            audit = read_run_artifact(
                home,
                profile_id=profile,
                run_id=run_id,
                artifact_type="audit-result",
            )["payload"]
            coverage = read_run_artifact(
                home,
                profile_id=profile,
                run_id=run_id,
                artifact_type="coverage",
            )["payload"]
            manifest = read_run_artifact(
                home,
                profile_id=profile,
                run_id=run_id,
                artifact_type="run-manifest",
            )["payload"]
            post_run = read_run_artifact(
                home,
                profile_id=profile,
                run_id=run_id,
                artifact_type="post-run-assessment",
            )["payload"]
            self.assertIn("uxEvaluation", analysis)
            self.assertEqual(audit["schemaVersion"], 2)
            self.assertEqual(audit["usageRulesLane"]["status"], "allowed")
            self.assertEqual(coverage["usageRulesLane"], audit["usageRulesLane"])
            self.assertIn("usageRulesLaneDigest", manifest)
            self.assertEqual(post_run["schemaVersion"], 2)
            before = {
                name: path.read_bytes()
                for name, path in source_paths.items()
            }

            decision_candidate = {
                "candidateResults": [],
                "selection": {"mode": "all_conflicts", "findingIds": []},
                "reason": "Reviewed for this exact finalized run.",
            }
            self.assertEqual(
                read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run_id,
                )["status"],
                "not_assessed",
            )
            preview = preview_judgment_decision(
                home,
                profile_id=profile,
                run_id=run_id,
                candidate=decision_candidate,
            )
            self.assertEqual(
                {name: path.read_bytes() for name, path in source_paths.items()},
                before,
            )
            applied = apply_judgment_decision(
                home,
                {
                    "schemaVersion": 1,
                    "profileId": profile,
                    "runId": run_id,
                    "candidate": decision_candidate,
                    "permission": {
                        **preview["permissionBinding"],
                        "granted": True,
                    },
                },
            )
            self.assertTrue(applied["changed"])
            self.assertEqual(
                {name: path.read_bytes() for name, path in source_paths.items()},
                before,
            )
            active = read_judgment_status(
                home,
                profile_id=profile,
                run_id=run_id,
            )
            self.assertEqual(active["status"], "active")
            judgment_path = run_directory / "judgment-assessment.sealed.json"
            self.assertTrue(judgment_path.is_file())
            sealed_judgment = judgment_path.read_bytes()

            revoked = revoke_judgment_decision(
                home,
                {
                    "schemaVersion": 1,
                    "profileId": profile,
                    "runId": run_id,
                    "permission": {
                        **active["revocationPermissionBinding"],
                        "granted": True,
                    },
                },
            )
            self.assertTrue(revoked["changed"])
            self.assertEqual(
                read_judgment_status(
                    home,
                    profile_id=profile,
                    run_id=run_id,
                )["status"],
                "revoked",
            )
            self.assertEqual(judgment_path.read_bytes(), sealed_judgment)
            self.assertEqual(
                {name: path.read_bytes() for name, path in source_paths.items()},
                before,
            )
            history = run_directory / "judgment-history"
            self.assertEqual(len(list(history.glob("*.json"))), 2)

    def test_exact_conflicts_can_resolve_but_not_assessed_remains_non_overridable(
        self,
    ) -> None:
        from guardian_core.judgment_assessment import (
            build_judgment_assessment,
            derive_effective_judgment,
        )

        temporary, _, context = provision_home()
        self.addCleanup(temporary.cleanup)
        _, incomplete_snapshot, _, _ = fixture()
        incomplete_snapshot["policyDigest"] = context["runPin"]["policyDigest"]
        assessment = build_judgment_assessment(
            run_pin=context["runPin"],
            rule_snapshot=incomplete_snapshot,
            analysis_attestation=context["analysisAttestation"],
            audit_result=context["auditResult"],
            candidate_results=[conflict_candidate()],
        )
        conflicts = sorted(
            finding["findingId"]
            for instance in assessment["instances"]
            if instance["rawStatus"] == "conflict"
            for finding in instance["findings"]
        )
        projection = derive_effective_judgment(
            assessment,
            {
                "active": True,
                "assessmentDigest": sha256_digest(assessment),
                "selectedFindingIds": conflicts,
            },
            enforcement_authority_lane=context["runManifest"][
                "enforcementAuthorityLane"
            ],
        )

        self.assertFalse(assessment["complete"])
        self.assertEqual(projection["effectiveStatus"], "not_assessed")
        not_assessed = [
            instance
            for instance in projection["instances"]
            if instance["rawStatus"] == "not_assessed"
        ]
        self.assertTrue(not_assessed)
        self.assertTrue(
            all(instance["effectiveStatus"] == "not_assessed" for instance in not_assessed)
        )
        self.assertTrue(all(not instance["appliedExceptions"] for instance in not_assessed))
        self.assertFalse(projection["productionReady"])


if __name__ == "__main__":
    unittest.main()
