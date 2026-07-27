from __future__ import annotations
import copy, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
)
from tests.flutter_runner_test_support import (
    create_minimal_flutter_project,
    runner_side_effect,
)
from tests.guardian_test_support import ingest_test_snapshot
from tests.test_cli_figma_dsg017 import ux_evidence
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_finalize_artifacts_dsg003 import COMPLETED_AT, STARTED_AT
from tests.test_judgment_assessment_dsg027 import conflict_candidate, fixture
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile
from tests.test_rule_activation_dsg025 import catalog_v2


def provision_real_flutter_v2_run(root: Path) -> tuple[Path, dict]:
    from guardian_core.evaluator_upgrade import (
        apply_evaluator_upgrade,
        preview_evaluator_upgrade,
    )
    from guardian_core.finalize import _finalize_run_at
    from guardian_core.preflight import preflight_snapshot
    from guardian_core.rule_activation import (
        apply_rule_activation,
        preview_rule_activation,
    )

    home = root / "guardian-home"
    profile = sample_profile()
    ingest_test_snapshot(
        home,
        profile,
        sample_catalog(),
        now=NOW,
        sequence=1,
    )
    catalog = catalog_v2(rules=[])
    for assets in catalog["registry"].values():
        for asset in assets:
            asset["codeMappings"] = []
    signed_catalog = attest_catalog(catalog, profile, sequence=2, issued_at=NOW)
    with patch("guardian_core.rule_activation._utc_now", return_value=NOW):
        activation_preview = preview_rule_activation(
            home,
            profile_id=profile["profileId"],
            catalog_document=signed_catalog,
        )
        activation = apply_rule_activation(
            home,
            {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "catalog": signed_catalog,
                "permission": {
                    **activation_preview["permissionBinding"],
                    "granted": True,
                },
            },
        )
    with patch("guardian_core.evaluator_upgrade._utc_now", return_value=NOW):
        evaluator_preview = preview_evaluator_upgrade(
            home,
            profile_id=profile["profileId"],
        )
        apply_evaluator_upgrade(
            home,
            {
                "schemaVersion": 1,
                "profileId": profile["profileId"],
                "permission": {
                    **evaluator_preview["permissionBinding"],
                    "granted": True,
                },
            },
        )

    project = create_minimal_flutter_project(root, name="flutter-product")
    with patch("guardian_core.preflight._utc_now", return_value=NOW):
        pin = preflight_snapshot(
            home,
            profile_id=profile["profileId"],
            run_id="run-real",
            policy_digest=activation["snapshot"]["policyDigest"],
            project_root=project,
        )["pin"]
    request_path = root / "audit-request.json"
    write_canonical(
        request_path,
        {
            "schemaVersion": 2,
            "adapter": "flutter",
            "projectRoot": str(project),
            "resolutions": [],
            "uxEvidence": ux_evidence(),
            "adapterEvidence": None,
        },
    )

    def result_v2(adapter_result: dict) -> None:
        adapter_result["schemaVersion"] = 2

    with patch(
        "guardian_core.cli.run_flutter_analysis",
        side_effect=runner_side_effect(result_v2),
    ):
        code, audit = invoke(
            home,
            [
                "audit",
                "--profile",
                profile["profileId"],
                "--run-id",
                pin["runId"],
                "--input",
                str(request_path),
            ],
        )
    if (
        code != 4
        or audit.get("schemaVersion") != 2
        or audit.get("designSystemLane", {}).get("status") != "allowed"
        or audit.get("usageRulesLane", {}).get("status") != "allowed"
    ):
        raise AssertionError(
            f"Real Flutter-v2 fixture did not audit cleanly: {code}: {audit}"
        )
    _finalize_run_at(
        home,
        profile_id=profile["profileId"],
        run_id=pin["runId"],
        audit_result=audit,
        build_plan=None,
        started_at=STARTED_AT,
        completed_at=COMPLETED_AT,
    )
    return home, pin


def attested_audit_digest(audit: dict) -> str:
    from guardian_core.canonical import sha256_digest

    projected = copy.deepcopy(audit)
    if projected.get("schemaVersion") == 2:
        projected["schemaVersion"] = 1
        projected.pop("usageRulesLane")
    return sha256_digest(projected)


def provision_home():
    from guardian_core.canonical import sha256_digest
    from guardian_core.policy import install_policy_anchor
    temporary = tempfile.TemporaryDirectory()
    home = Path(temporary.name)
    key = home / "catalog-authority-input.pem"
    key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
    policy = install_policy_anchor(home, catalog_authority_public_key=key).digest
    pin, snapshot, analysis, audit = fixture()
    pin["policyDigest"] = snapshot["policyDigest"] = analysis["policyDigest"] = audit["policyDigest"] = policy
    snapshot["rules"] = [snapshot["rules"][0]]
    snapshot["rulesDigest"] = sha256_digest(snapshot["rules"])
    analysis["auditResultDigest"] = attested_audit_digest(audit)
    return temporary, home, {
        "runPin": pin, "profile": {"profileId": pin["profileId"]},
        "ruleSnapshot": snapshot, "analysisAttestation": analysis, "auditResult": audit,
        "runManifest": {"schemaVersion": 2, "runId": pin["runId"], "profileId": pin["profileId"],
            "policyDigest": policy, "enforcementAuthorityLane": {
                "schemaVersion": 1, "status": "not_assessed", "provider": None, "attestation": None}},
        "evaluatorAuthorization": {"schemaVersion": 1, "profileId": pin["profileId"],
            "authorizationDigest": "7" * 64},
    }

def candidate(*, ids=None, all_conflicts=True):
    return {"candidateResults": [conflict_candidate()],
        "selection": {"mode": "all_conflicts", "findingIds": []} if all_conflicts
            else {"mode": "finding_ids", "findingIds": ids or []},
        "reason": "Accepted for this exact reviewed run."}

class JudgmentDecisionTest(unittest.TestCase):
    def test_preview_apply_and_denial(self):
        from guardian_core.judgment_decisions import apply_judgment_decision, preview_judgment_decision, read_judgment_status
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=candidate())
            self.assertEqual(preview["status"], "permission_required")
            self.assertTrue(preview["explanation"]["findings"])
            denied = apply_judgment_decision(home, {"schemaVersion": 1, "profileId": profile,
                "runId": run, "candidate": candidate(),
                "permission": {**preview["permissionBinding"], "granted": False}})
            self.assertEqual(denied["status"], "denied")
            self.assertFalse((home / "profiles" / profile / "audits" / run).exists())
            bundle = {"schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": candidate(), "permission": {**preview["permissionBinding"], "granted": True}}
            self.assertTrue(apply_judgment_decision(home, bundle)["changed"])
            self.assertFalse(apply_judgment_decision(home, bundle)["changed"])
            status = read_judgment_status(home, profile_id=profile, run_id=run)
            self.assertEqual((status["status"], status["effectiveProjection"]["effectiveStatus"]), ("active", "allowed"))
            self.assertFalse(status["effectiveProjection"]["productionReady"])

    def test_selection_blockers_and_all_binding_mutations_fail(self):
        from guardian_core.canonical import sha256_digest
        from guardian_core.judgment_assessment import build_judgment_assessment
        from guardian_core.judgment_decisions import JudgmentDecisionIntegrityError, apply_judgment_decision, preview_judgment_decision
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        assessment = build_judgment_assessment(run_pin=context["runPin"], rule_snapshot=context["ruleSnapshot"],
            analysis_attestation=context["analysisAttestation"], audit_result=context["auditResult"],
            candidate_results=candidate()["candidateResults"])
        finding = next(item for item in assessment["instances"] if item["rawStatus"] == "conflict")["findings"][0]["findingId"]
        selected = candidate(ids=[finding], all_conflicts=False)
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=selected)
            for field, value in preview["permissionBinding"].items():
                changed = copy.deepcopy(preview["permissionBinding"])
                changed[field] = 2 if isinstance(value, int) else ("0" * 64 if isinstance(value, str) and len(value) == 64 else "changed")
                with self.subTest(field=field), self.assertRaises(JudgmentDecisionIntegrityError):
                    apply_judgment_decision(home, {"schemaVersion": 1, "profileId": profile, "runId": run,
                        "candidate": selected, "permission": {**changed, "granted": True}})
            for ids in ([finding, finding], ["finding-" + "0" * 24]):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    preview_judgment_decision(home, profile_id=profile, run_id=run,
                        candidate=candidate(ids=ids, all_conflicts=False))
            blocked = copy.deepcopy(context)
            blocked["auditResult"]["designSystemLane"]["status"] = "invalid"
            blocked["analysisAttestation"]["auditResultDigest"] = attested_audit_digest(blocked["auditResult"])
            with patch("guardian_core.judgment_decisions._reopen_context", return_value=blocked):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=selected)

    def test_not_assessed_empty_reason_replay_and_partial_recovery(self):
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError, apply_judgment_decision,
            preview_judgment_decision, read_judgment_status,
        )
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        incomplete = copy.deepcopy(context)
        _, original_snapshot, _, _ = fixture()
        original_snapshot["policyDigest"] = context["runPin"]["policyDigest"]
        incomplete["ruleSnapshot"] = original_snapshot
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=incomplete):
            with self.assertRaises(JudgmentDecisionIntegrityError):
                preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=candidate())
        empty = candidate(); empty["reason"] = ""
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(home, profile_id=profile, run_id=run, candidate=empty)
            bundle = {"schemaVersion": 1, "profileId": profile, "runId": run,
                "candidate": empty, "permission": {**preview["permissionBinding"], "granted": True}}
            with patch("guardian_core.judgment_decisions.contained_atomic_write_json", side_effect=OSError("interrupted")):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    apply_judgment_decision(home, bundle)
            self.assertTrue(apply_judgment_decision(home, bundle)["changed"])
            self.assertEqual(read_judgment_status(home, profile_id=profile, run_id=run)["status"], "active")
            divergent = copy.deepcopy(bundle); divergent["candidate"]["reason"] = "different"
            with self.assertRaises(JudgmentDecisionIntegrityError):
                apply_judgment_decision(home, divergent)
            history = home / "profiles" / profile / "audits" / run / "judgment-history"
            record = next(history.glob("*.json"))
            duplicate = history / ("00000002-" + record.stem.split("-", 1)[1] + ".json")
            duplicate.write_bytes(record.read_bytes())
            with self.assertRaises(JudgmentDecisionIntegrityError):
                read_judgment_status(home, profile_id=profile, run_id=run)
    def test_interrupted_approval_rejects_divergent_candidate(self):
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError, apply_judgment_decision,
            preview_judgment_decision,
        )
        temporary, home, context = provision_home(); self.addCleanup(temporary.cleanup)
        profile, run = context["runPin"]["profileId"], context["runPin"]["runId"]
        original = candidate(); original["reason"] = "original"
        divergent = copy.deepcopy(original); divergent["reason"] = "divergent"
        with patch("guardian_core.judgment_decisions._reopen_context", return_value=context):
            preview = preview_judgment_decision(
                home, profile_id=profile, run_id=run, candidate=original
            )
            permission = {**preview["permissionBinding"], "granted": True}
            with patch(
                "guardian_core.judgment_decisions.contained_atomic_write_json",
                side_effect=OSError("interrupted"),
            ):
                with self.assertRaises(JudgmentDecisionIntegrityError):
                    apply_judgment_decision(home, {
                        "schemaVersion": 1, "profileId": profile, "runId": run,
                        "candidate": original, "permission": permission,
                    })
            with self.assertRaises(JudgmentDecisionIntegrityError):
                apply_judgment_decision(home, {
                    "schemaVersion": 1, "profileId": profile, "runId": run,
                    "candidate": divergent, "permission": permission,
                })

    def test_real_flutter_v2_reopens_pinned_config_and_decision_lifecycle(self):
        from guardian_core.adapter_dispatch import build_pinned_adapter_config
        from guardian_core.judgment_decisions import (
            JudgmentDecisionIntegrityError,
            apply_judgment_decision,
            preview_judgment_decision,
            read_judgment_status,
            revoke_judgment_decision,
        )

        with tempfile.TemporaryDirectory() as directory:
            home, pin = provision_real_flutter_v2_run(Path(directory))
            decision_candidate = {
                "candidateResults": [],
                "selection": {"mode": "all_conflicts", "findingIds": []},
                "reason": "Reviewed for this exact finalized run.",
            }
            preview = preview_judgment_decision(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                candidate=decision_candidate,
            )
            self.assertEqual(preview["status"], "permission_required")
            bundle = {
                "schemaVersion": 1,
                "profileId": pin["profileId"],
                "runId": pin["runId"],
                "candidate": decision_candidate,
                "permission": {
                    **preview["permissionBinding"],
                    "granted": True,
                },
            }
            self.assertTrue(apply_judgment_decision(home, bundle)["changed"])
            active = read_judgment_status(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
            )
            self.assertEqual(active["status"], "active")
            revoked = revoke_judgment_decision(
                home,
                {
                    "schemaVersion": 1,
                    "profileId": pin["profileId"],
                    "runId": pin["runId"],
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
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                )["status"],
                "revoked",
            )

            config_context, config = build_pinned_adapter_config(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                adapter="flutter",
            )
            mismatched = copy.deepcopy(config)
            mismatched["configDigest"] = "0" * 64
            with patch(
                "guardian_core.judgment_decisions.build_pinned_adapter_config",
                return_value=(config_context, mismatched),
            ), self.assertRaisesRegex(
                JudgmentDecisionIntegrityError,
                "adapter config",
            ):
                preview_judgment_decision(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    candidate=decision_candidate,
                )

if __name__ == "__main__": unittest.main()
