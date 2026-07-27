from __future__ import annotations

import copy
import json
import tempfile
from datetime import datetime, timedelta, timezone
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, RefResolver, ValidationError

from tests.test_audit_dsg003 import (
    allowed_ux_check,
    complete_adapter,
    sample_pin,
    sample_project_evidence,
    sample_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"


def usage_evidence(
    *,
    status: str = "allowed",
    active: list[str] | None = None,
    assessed: list[str] | None = None,
    violated: list[str] | None = None,
    informative: list[str] | None = None,
    not_assessed: list[dict[str, str]] | None = None,
    diagnostics: list[dict[str, str]] | None = None,
) -> dict:
    return {
        "schemaVersion": 1,
        "status": status,
        "evaluatorId": "guardian-flutter-usage-rules-v2",
        "evaluatorContractDigest": "1" * 64,
        "authorizationDigest": "2" * 64,
        "ruleSnapshotId": "3" * 64,
        "rulesDigest": "4" * 64,
        "activeRuleIds": active or [],
        "assessedRuleIds": assessed or [],
        "violatedRuleIds": violated or [],
        "informativeRuleIds": informative or [],
        "notAssessed": not_assessed or [],
        "diagnostics": diagnostics or [],
    }


def legacy_usage_diagnostic(identifier: str = "legacy-usage-1") -> dict:
    return {
        "diagnosticId": identifier,
        "category": "components",
        "kind": "violation",
        "message": "An active machine usage rule was violated.",
        "evidence": {"code": "guardian_usage_rule"},
    }


def usage_diagnostic(
    *, rule_id: str = "rule.card.maximum", inherited: str = "legacy-usage-1"
) -> dict:
    return {
        "diagnosticId": "usage-rule-1",
        "ruleId": rule_id,
        "reasonCode": "machine_rule_violation",
        "inheritedDiagnosticId": inherited,
    }


def evaluate_usage(
    evidence: dict,
    *,
    diagnostics: list[dict] | None = None,
    component_status: str = "allowed",
    supported: bool = True,
    verified_snapshot: dict | None = None,
):
    from guardian_core.audit import evaluate_audit

    adapter = complete_adapter(diagnostics=diagnostics)
    adapter["supported"] = supported
    adapter["categories"]["components"]["status"] = component_status
    if component_status != "allowed":
        adapter["categories"]["components"]["assessedItems"] = 0
    return evaluate_audit(
        run_pin=sample_pin(),
        adapter_result=adapter,
        resolutions=[],
        ux_checks=[allowed_ux_check()],
        project_evidence=sample_project_evidence(),
        verified_snapshot=verified_snapshot or sample_snapshot(),
        usage_rules_evidence=evidence,
    )


def schema_validator(name: str) -> Draft202012Validator:
    schemas = {
        candidate["$id"]: candidate
        for path in SCHEMA_ROOT.glob("*.schema.json")
        for candidate in [json.loads(path.read_text(encoding="utf-8"))]
    }
    schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        resolver=RefResolver.from_schema(schema, store=schemas),
    )


class UsageRulesAuditLaneTest(unittest.TestCase):
    def test_v1_output_remains_exact_and_v2_projects_back_to_it(self) -> None:
        from guardian_core.audit import evaluate_audit, project_audit_result_v1

        arguments = {
            "run_pin": sample_pin(),
            "adapter_result": complete_adapter(),
            "resolutions": [],
            "ux_checks": [allowed_ux_check()],
            "project_evidence": sample_project_evidence(),
            "verified_snapshot": sample_snapshot(),
        }
        inherited = evaluate_audit(**arguments).result
        current = evaluate_audit(
            **arguments,
            usage_rules_evidence=usage_evidence(
                informative=["rule.guidance.only"]
            ),
        ).result

        self.assertEqual(inherited["schemaVersion"], 1)
        self.assertNotIn("usageRulesLane", inherited)
        self.assertEqual(current["schemaVersion"], 2)
        self.assertEqual(current["usageRulesLane"]["status"], "allowed")
        self.assertEqual(
            current["usageRulesLane"]["informativeRuleIds"],
            ["rule.guidance.only"],
        )
        self.assertEqual(project_audit_result_v1(current), inherited)

    def test_embedded_adapter_evidence_is_used_and_explicit_evidence_must_agree(
        self,
    ) -> None:
        from guardian_core.audit import AuditIntegrityError, evaluate_audit

        evidence = usage_evidence(
            active=["rule.card.maximum"],
            assessed=["rule.card.maximum"],
        )
        adapter = complete_adapter()
        adapter["usageRulesEvidence"] = copy.deepcopy(evidence)
        arguments = {
            "run_pin": sample_pin(),
            "adapter_result": adapter,
            "resolutions": [],
            "ux_checks": [allowed_ux_check()],
            "project_evidence": sample_project_evidence(),
            "verified_snapshot": sample_snapshot(),
        }

        embedded = evaluate_audit(**arguments)
        self.assertEqual(embedded.result["schemaVersion"], 2)
        self.assertEqual(
            embedded.result["usageRulesLane"]["assessedRuleIds"],
            ["rule.card.maximum"],
        )

        divergent = copy.deepcopy(evidence)
        divergent["rulesDigest"] = "5" * 64
        with self.assertRaisesRegex(
            AuditIntegrityError,
            "differs from the normalized adapter evidence",
        ):
            evaluate_audit(
                **arguments,
                usage_rules_evidence=divergent,
            )

    def test_truth_table_and_informative_rules_are_non_gating(self) -> None:
        from guardian_core.contracts import ExitCode

        allowed = evaluate_usage(
            usage_evidence(
                active=["rule.card.maximum"],
                assessed=["rule.card.maximum"],
                informative=["rule.guidance.only"],
            )
        )
        self.assertEqual(allowed.result["usageRulesLane"]["status"], "allowed")
        self.assertEqual(
            allowed.result["usageRulesLane"]["informativeRuleIds"],
            ["rule.guidance.only"],
        )

        conflict = evaluate_usage(
            usage_evidence(
                status="conflict",
                active=["rule.card.maximum"],
                assessed=["rule.card.maximum"],
                violated=["rule.card.maximum"],
                diagnostics=[usage_diagnostic()],
            ),
            diagnostics=[legacy_usage_diagnostic()],
        )
        self.assertEqual(conflict.result["usageRulesLane"]["status"], "conflict")
        self.assertEqual(conflict.exit_code, ExitCode.VIOLATION_OR_SENTINEL)

        conflict_with_incomplete_rule = evaluate_usage(
            usage_evidence(
                status="conflict",
                active=["rule.card.maximum", "rule.card.parent"],
                assessed=["rule.card.maximum"],
                violated=["rule.card.maximum"],
                not_assessed=[
                    {
                        "ruleId": "rule.card.parent",
                        "reasonCode": "incomplete_construction_graph",
                    }
                ],
                diagnostics=[usage_diagnostic()],
            ),
            diagnostics=[legacy_usage_diagnostic()],
            component_status="not_assessed",
        )
        self.assertEqual(
            conflict_with_incomplete_rule.result["usageRulesLane"]["status"],
            "conflict",
        )
        self.assertEqual(
            conflict_with_incomplete_rule.exit_code,
            ExitCode.VIOLATION_OR_SENTINEL,
        )

        incomplete = evaluate_usage(
            usage_evidence(
                status="not_assessed",
                active=["rule.card.maximum"],
                not_assessed=[
                    {
                        "ruleId": "rule.card.maximum",
                        "reasonCode": "incomplete_construction_graph",
                    }
                ],
            ),
            component_status="not_assessed",
        )
        self.assertEqual(
            incomplete.result["usageRulesLane"]["status"], "not_assessed"
        )
        self.assertEqual(
            incomplete.exit_code,
            ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE,
        )

        judgment = evaluate_usage(
            usage_evidence(
                status="not_assessed",
                not_assessed=[
                    {
                        "ruleId": "rule.requires-judgment",
                        "reasonCode": "judgment_attestation_unavailable",
                    }
                ],
            ),
            component_status="not_assessed",
        )
        self.assertEqual(judgment.result["usageRulesLane"]["status"], "not_assessed")

        unsupported = evaluate_usage(
            usage_evidence(
                status="unsupported",
                active=["rule.card.maximum"],
                not_assessed=[
                    {
                        "ruleId": "rule.card.maximum",
                        "reasonCode": "unsupported_adapter",
                    }
                ],
            ),
            component_status="unsupported",
            supported=False,
        )
        self.assertEqual(unsupported.result["usageRulesLane"]["status"], "unsupported")

        unavailable_snapshot = sample_snapshot()
        unavailable_snapshot.update(
            {
                "sourceAvailable": False,
                "sourceComplete": True,
                "lastSuccessfulRefreshAt": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat().replace("+00:00", "Z"),
                "sourceEvidence": {"refreshAttempted": True},
            }
        )
        source_blocked = evaluate_usage(
            usage_evidence(),
            verified_snapshot=unavailable_snapshot,
        )
        self.assertEqual(
            source_blocked.result["usageRulesLane"]["status"],
            "source_unavailable",
        )
        self.assertEqual(
            source_blocked.exit_code,
            ExitCode.SOURCE_UNAVAILABLE_STALE_OR_INCOMPLETE,
        )

    def test_lane_disagreement_and_noncanonical_evidence_fail_closed(self) -> None:
        from guardian_core.audit import AuditIntegrityError, derive_audit_exit_code

        conflicting = usage_evidence(
            status="conflict",
            active=["rule.card.maximum"],
            assessed=["rule.card.maximum"],
            violated=["rule.card.maximum"],
            diagnostics=[usage_diagnostic()],
        )
        with self.assertRaisesRegex(AuditIntegrityError, "inherited"):
            evaluate_usage(conflicting)

        unsorted = usage_evidence(
            active=["rule.z", "rule.a"],
            assessed=["rule.a", "rule.z"],
        )
        with self.assertRaisesRegex(AuditIntegrityError, "sorted"):
            evaluate_usage(unsorted)

        result = evaluate_usage(
            conflicting,
            diagnostics=[legacy_usage_diagnostic()],
        ).result
        tampered = copy.deepcopy(result)
        tampered["usageRulesLane"]["violatedRuleIds"] = []
        with self.assertRaises(AuditIntegrityError):
            derive_audit_exit_code(tampered)

    def test_additive_v2_schemas_are_strict_and_v1_schema_stays_v1(self) -> None:
        v1 = evaluate_usage(usage_evidence()).result
        projected = copy.deepcopy(v1)
        projected["schemaVersion"] = 1
        projected.pop("usageRulesLane")

        schema_validator("usage-rules-evidence.schema.json").validate(usage_evidence())
        schema_validator("audit-result-v2.schema.json").validate(v1)
        schema_validator("audit-result.schema.json").validate(projected)
        with self.assertRaises(ValidationError):
            schema_validator("audit-result.schema.json").validate(v1)

        extra = usage_evidence()
        extra["ruleStatements"] = ["private prose"]
        with self.assertRaises(ValidationError):
            schema_validator("usage-rules-evidence.schema.json").validate(extra)

    def test_readable_report_has_three_separate_compliance_sections(self) -> None:
        from guardian_core.run_artifacts import render_audit_report, seal_run_artifact
        from tests.test_finalize_artifacts_dsg003 import provision_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-usage-report")
            from tests.test_finalize_artifacts_dsg003 import clean_audit

            audit = clean_audit(pin).result
            audit["schemaVersion"] = 2
            audit["usageRulesLane"] = usage_evidence(
                informative=["rule.guidance.only"]
            )
            audit["usageRulesLane"].pop("schemaVersion")
            audit["usageRulesLane"].pop("status")
            audit["usageRulesLane"] = {
                "status": "allowed",
                **audit["usageRulesLane"],
            }
            envelope = seal_run_artifact(
                home,
                artifact_type="audit-result",
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                payload=audit,
            )

            report = render_audit_report(home, envelope)

            self.assertIn("## Design-system compliance lane", report)
            self.assertIn("## Usage Rules compliance lane", report)
            self.assertIn("## UX/accessibility quality lane", report)
            self.assertIn("rule.guidance.only", report)
            self.assertNotIn("authorizationDigest", report)
            self.assertNotIn("ruleStatements", report)

    def test_post_run_v2_records_exact_rule_outcomes_without_source_content(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.post_run import (
            PostRunAssessmentIntegrityError,
            build_post_run_assessment,
        )

        evaluation = evaluate_usage(
            usage_evidence(
                status="not_assessed",
                active=["rule.card.maximum"],
                not_assessed=[
                    {
                        "ruleId": "rule.card.maximum",
                        "reasonCode": "incomplete_construction_graph",
                    }
                ],
                informative=["rule.guidance.only"],
            ),
            component_status="not_assessed",
        )
        audit = evaluation.result
        manifest = {
            "schemaVersion": 2,
            "runId": audit["runId"],
            "profileId": audit["profileId"],
            "snapshotId": audit["snapshotId"],
            "policyDigest": audit["policyDigest"],
            "exitCode": int(evaluation.exit_code),
            "productionReady": audit["productionReady"],
            "usageRulesLaneDigest": sha256_digest(audit["usageRulesLane"]),
        }

        assessment = build_post_run_assessment(
            audit_result=audit,
            run_manifest=manifest,
            run_manifest_digest="5" * 64,
            runtime_version="0.3.6",
        )

        self.assertEqual(assessment["schemaVersion"], 2)
        self.assertEqual(assessment["statuses"]["usageRules"], "not_assessed")
        self.assertEqual(assessment["counts"]["assessedUsageRules"], 0)
        self.assertEqual(assessment["counts"]["unassessedUsageRules"], 1)
        self.assertEqual(
            assessment["usageRules"]["notAssessed"],
            [
                {
                    "ruleId": "rule.card.maximum",
                    "reasonCode": "incomplete_construction_graph",
                }
            ],
        )
        self.assertEqual(
            assessment["usageRules"]["informativeRuleIds"],
            ["rule.guidance.only"],
        )
        self.assertEqual(
            assessment["evidenceDigests"]["usageRulesLane"],
            sha256_digest(audit["usageRulesLane"]),
        )
        schema_validator("post-run-assessment-v2.schema.json").validate(assessment)

        manifest["usageRulesLaneDigest"] = "0" * 64
        with self.assertRaisesRegex(
            PostRunAssessmentIntegrityError, "Usage Rules lane digest"
        ):
            build_post_run_assessment(
                audit_result=audit,
                run_manifest=manifest,
                run_manifest_digest="5" * 64,
                runtime_version="0.3.6",
            )

    def test_finalize_seals_v2_lane_coverage_manifest_report_and_self_check(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.finalize import finalize_run
        from guardian_core.run_artifacts import (
            read_run_artifact,
            seal_run_artifact,
            write_run_artifact,
        )
        from tests.test_finalize_artifacts_dsg003 import (
            NOW,
            clean_audit,
            provision_run,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-usage-finalize")
            audit = clean_audit(pin).result
            audit["schemaVersion"] = 2
            lane = usage_evidence(informative=["rule.guidance.only"])
            lane.pop("schemaVersion")
            audit["usageRulesLane"] = lane

            analysis_payload = {
                "schemaVersion": 1,
                "runId": pin["runId"],
                "profileId": pin["profileId"],
                "policyDigest": pin["policyDigest"],
                "runnerEvidence": {
                    "normalizedAdapterResult": {
                        "usageRulesEvidence": usage_evidence(
                            informative=["rule.guidance.only"]
                        )
                    }
                },
            }
            analysis_envelope = seal_run_artifact(
                home,
                artifact_type="analysis-attestation",
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                payload=analysis_payload,
            )
            write_run_artifact(home, analysis_envelope)
            audit["analysisAttestationDigest"] = analysis_envelope["payloadDigest"]

            with (
                patch(
                    "guardian_core.finalize.build_pinned_adapter_config",
                    return_value=(
                        Path("adapter-config.json"),
                        {"configDigest": audit["coverage"]["configDigest"]},
                    ),
                ),
                patch(
                    "guardian_core.finalize.verify_analysis_attestation"
                ) as verify_attestation,
                patch(
                    "guardian_core.finalize._utc_now",
                    return_value=NOW + timedelta(days=8),
                ),
            ):
                finalized = finalize_run(
                    home,
                    profile_id=pin["profileId"],
                    run_id=pin["runId"],
                    audit_result=audit,
                    build_plan=None,
                )

            projected_for_attestation = verify_attestation.call_args.kwargs[
                "audit_result"
            ]
            self.assertEqual(projected_for_attestation["schemaVersion"], 1)
            self.assertNotIn("usageRulesLane", projected_for_attestation)

            sealed_audit = read_run_artifact(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                artifact_type="audit-result",
            )["payload"]
            sealed_coverage = read_run_artifact(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                artifact_type="coverage",
            )["payload"]
            sealed_post_run = read_run_artifact(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                artifact_type="post-run-assessment",
            )["payload"]

            self.assertEqual(sealed_audit["schemaVersion"], 2)
            self.assertEqual(sealed_audit["designSystemLane"]["status"], "stale")
            self.assertEqual(sealed_audit["usageRulesLane"]["status"], "stale")
            self.assertEqual(
                sealed_coverage["usageRulesLane"], sealed_audit["usageRulesLane"]
            )
            self.assertEqual(sealed_coverage["schemaVersion"], 2)
            self.assertEqual(finalized.manifest["schemaVersion"], 2)
            self.assertEqual(
                finalized.manifest["usageRulesLaneDigest"],
                sha256_digest(sealed_audit["usageRulesLane"]),
            )
            self.assertEqual(sealed_post_run["schemaVersion"], 2)
            self.assertEqual(
                sealed_post_run["usageRules"]["informativeRuleIds"],
                ["rule.guidance.only"],
            )
            self.assertIn(
                "## Usage Rules compliance lane",
                finalized.artifact_paths["readable-report"].read_text(
                    encoding="utf-8"
                ),
            )
            schema_validator("run-manifest-v2.schema.json").validate(
                finalized.manifest
            )
            schema_validator("post-run-assessment-v2.schema.json").validate(
                sealed_post_run
            )


    def test_finalize_rejects_usage_lane_that_differs_from_sealed_runner(self) -> None:
        from guardian_core.finalize import FinalizationError, finalize_run
        from guardian_core.run_artifacts import seal_run_artifact, write_run_artifact
        from tests.test_finalize_artifacts_dsg003 import NOW, clean_audit, provision_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-usage-finalize-drift")
            evidence = usage_evidence()
            audit = clean_audit(pin).result
            audit["schemaVersion"] = 2
            lane = copy.deepcopy(evidence)
            lane.pop("schemaVersion")
            lane["rulesDigest"] = "9" * 64
            audit["usageRulesLane"] = lane

            analysis_envelope = seal_run_artifact(
                home,
                artifact_type="analysis-attestation",
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                payload={
                    "schemaVersion": 1,
                    "runId": pin["runId"],
                    "profileId": pin["profileId"],
                    "policyDigest": pin["policyDigest"],
                    "runnerEvidence": {
                        "normalizedAdapterResult": {"usageRulesEvidence": evidence}
                    },
                },
            )
            write_run_artifact(home, analysis_envelope)
            audit["analysisAttestationDigest"] = analysis_envelope["payloadDigest"]

            with (
                patch(
                    "guardian_core.finalize.build_pinned_adapter_config",
                    return_value=(
                        Path("adapter-config.json"),
                        {"configDigest": audit["coverage"]["configDigest"]},
                    ),
                ),
                patch("guardian_core.finalize.verify_analysis_attestation"),
                patch("guardian_core.finalize._utc_now", return_value=NOW),
            ):
                with self.assertRaisesRegex(FinalizationError, "sealed runner"):
                    finalize_run(
                        home,
                        profile_id=pin["profileId"],
                        run_id=pin["runId"],
                        audit_result=audit,
                        build_plan=None,
                    )

    def test_judgment_projection_cannot_hide_or_rewrite_machine_usage_rules(self) -> None:
        from guardian_core.canonical import canonical_json_bytes, sha256_digest
        from guardian_core.judgment_assessment import (
            build_judgment_assessment,
            derive_effective_judgment,
        )
        from tests.test_judgment_decisions_dsg027 import (
            attested_audit_digest,
            candidate,
            provision_home,
        )

        temporary, _, context = provision_home()
        self.addCleanup(temporary.cleanup)
        context["auditResult"]["usageRulesLane"] = {
            "status": "conflict",
            "violatedRuleIds": ["rule.machine.maximum"],
            "suppressions": ["ignore: rule.machine.maximum"],
        }
        context["analysisAttestation"]["auditResultDigest"] = attested_audit_digest(
            context["auditResult"]
        )
        before_audit = canonical_json_bytes(context["auditResult"])
        before_lane = canonical_json_bytes(context["auditResult"]["usageRulesLane"])
        assessment = build_judgment_assessment(
            run_pin=context["runPin"],
            rule_snapshot=context["ruleSnapshot"],
            analysis_attestation=context["analysisAttestation"],
            audit_result=context["auditResult"],
            candidate_results=candidate()["candidateResults"],
        )
        conflicts = sorted(
            finding["findingId"]
            for instance in assessment["instances"]
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

        self.assertEqual(projection["effectiveStatus"], "allowed")
        self.assertFalse(projection["nonJudgmentBlockersClear"])
        self.assertFalse(projection["productionReady"])
        self.assertEqual(canonical_json_bytes(context["auditResult"]), before_audit)
        self.assertEqual(
            canonical_json_bytes(context["auditResult"]["usageRulesLane"]),
            before_lane,
        )

if __name__ == "__main__":
    unittest.main()
