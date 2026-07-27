from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

from guardian_core.canonical import sha256_digest
from guardian_core.ux_evaluator import (
    REQUIRED_FLOW_AREAS,
    REQUIRED_SCREEN_AREAS,
    evaluate_final_flow,
)


SCREEN = "a" * 64
FLOW = "f" * 64
SOURCE_CUT = {"catalogDigest": "c" * 64, "repositoryCommit": "abc1234"}


def _observation(target_digest: str, area: str, *, allowed: bool = True) -> dict:
    return {
        "checkId": f"{target_digest[:8]}-{area}",
        "targetDigest": target_digest,
        "area": area,
        "operator": "equals",
        "observed": allowed,
        "expected": True,
        "evidenceDigest": sha256_digest(f"{target_digest}:{area}".encode()),
    }


def judgment_rule(rule_id: str, applies_to: dict | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "judgment",
        "statement": "Use the approved visual judgment.",
        "appliesTo": applies_to or {"kind": "system"},
        "provenance": {"origin": "document", "docRef": "design/rules"},
    }


def fixture(*, gap: bool = False) -> tuple[dict, dict, dict, dict]:
    run_pin = {
        "schemaVersion": 1,
        "runId": "run-judgment",
        "profileId": "example-company",
        "profileDigest": "1" * 64,
        "snapshotId": "2" * 64,
        "catalogDigest": "3" * 64,
        "policyDigest": "4" * 64,
        "sourceCut": copy.deepcopy(SOURCE_CUT),
    }
    rules = [
        judgment_rule("rule.system-balance"),
        judgment_rule(
            "rule.component-tone",
            {"kind": "component", "identity": "button.primary"},
        ),
    ]
    rule_snapshot = {
        "schemaVersion": 2,
        "profileId": run_pin["profileId"],
        "profileDigest": run_pin["profileDigest"],
        "snapshotId": run_pin["snapshotId"],
        "catalogDigest": run_pin["catalogDigest"],
        "policyDigest": run_pin["policyDigest"],
        "rules": rules,
        "rulesDigest": sha256_digest(rules),
    }
    observations = [
        _observation(SCREEN, area, allowed=not (gap and area == "contrast"))
        for area in REQUIRED_SCREEN_AREAS
    ] + [_observation(FLOW, area) for area in REQUIRED_FLOW_AREAS]
    ux_target = {"flowDigest": FLOW, "screenDigests": [SCREEN]}
    ux_evaluation = evaluate_final_flow(
        target=ux_target,
        observations=observations,
        source_cut=SOURCE_CUT,
    )
    audit_result = {
        "schemaVersion": 2,
        "runId": run_pin["runId"],
        "profileId": run_pin["profileId"],
        "snapshotId": run_pin["snapshotId"],
        "policyDigest": run_pin["policyDigest"],
        "designSystemLane": {"status": "allowed"},
        "usageRulesLane": {"status": "allowed"},
        "coverage": {"status": "allowed"},
        "uxAccessibilityLane": {"status": "not_assessed", "checks": []},
        "productionReady": False,
    }
    runner = {
        "schemaVersion": 1,
        "adapter": "flutter",
        "adapterResult": {"adapter": "flutter", "binding": {}},
        "project": {},
    }
    attested_audit = copy.deepcopy(audit_result)
    attested_audit["schemaVersion"] = 1
    attested_audit.pop("usageRulesLane")
    analysis_attestation = {
        "schemaVersion": 1,
        "runId": run_pin["runId"],
        "profileId": run_pin["profileId"],
        "snapshotId": run_pin["snapshotId"],
        "policyDigest": run_pin["policyDigest"],
        "configDigest": "5" * 64,
        "runnerEvidenceDigest": sha256_digest(runner),
        "runnerEvidence": runner,
        "auditResultDigest": sha256_digest(attested_audit),
        "uxTarget": ux_target,
        "uxEvaluation": ux_evaluation,
        "uxEvaluationDigest": sha256_digest(ux_evaluation),
    }
    return run_pin, rule_snapshot, analysis_attestation, audit_result


def conflict_candidate() -> dict:
    return {
        "ruleId": "rule.system-balance",
        "targetId": None,
        "status": "conflict",
        "incompletenessReason": None,
        "findings": [
            {
                "explanation": "The primary hierarchy competes with the secondary action.",
                "impact": "The intended next action is harder to identify.",
                "evidenceReferences": [
                    {"artifact": "review-capture", "digest": "6" * 64}
                ],
                "correction": "Reduce the secondary action emphasis and evaluate again.",
            }
        ],
    }


class JudgmentAssessmentTest(unittest.TestCase):
    def build(self, candidates: list[dict] | None = None, *, gap: bool = False) -> dict:
        from guardian_core.judgment_assessment import build_judgment_assessment

        run_pin, snapshot, attestation, audit = fixture(gap=gap)
        return build_judgment_assessment(
            run_pin=run_pin,
            rule_snapshot=snapshot,
            analysis_attestation=attestation,
            audit_result=audit,
            candidate_results=candidates if candidates is not None else [conflict_candidate()],
        )

    def test_builder_derives_ids_bindings_and_incomplete_occurrence_fallback(self) -> None:
        assessment = self.build()
        self.assertEqual(
            assessment["activeRuleIds"],
            ["rule.system-balance", "rule.component-tone"],
        )
        self.assertEqual(assessment["rawStatus"], "conflict")
        self.assertFalse(assessment["complete"])
        self.assertTrue(assessment["nonJudgmentBlockersClear"])
        self.assertEqual(
            [item["instanceId"] for item in assessment["instances"]],
            sorted(item["instanceId"] for item in assessment["instances"]),
        )
        conflict = next(
            item for item in assessment["instances"] if item["ruleId"] == "rule.system-balance"
        )
        self.assertEqual(conflict["rawStatus"], "conflict")
        self.assertEqual(
            set(conflict["findings"][0]),
            {
                "findingId", "ruleId", "targetId", "explanation", "impact",
                "evidenceReferences", "correction", "evidenceDigest",
            },
        )
        unavailable = next(
            item for item in assessment["instances"] if item["ruleId"] == "rule.component-tone"
        )
        self.assertEqual(unavailable["target"]["kind"], "coverage")
        self.assertEqual(unavailable["rawStatus"], "not_assessed")
        self.assertEqual(
            unavailable["incompletenessReason"],
            "sealed_occurrence_inventory_unavailable",
        )
        self.assertTrue(all(len(value) == 64 for value in assessment["bindings"].values()))

    def test_fabricated_unsealed_figma_occurrence_fails_closed(self) -> None:
        from guardian_core.judgment_assessment import build_judgment_assessment

        pin, snapshot, attestation, audit = fixture()
        runner = {
            "schemaVersion": 1,
            "adapter": "figma",
            "adapterResult": {
                "source": {"complete": True},
                "analysis": {
                    "complete": True,
                    "assessedNodes": 1,
                    "totalNodes": 1,
                    "assessedFields": 1,
                    "totalFields": 1,
                },
                "observations": [
                    {
                        "kind": "asset",
                        "category": "components",
                        "nodeId": "1:2",
                        "field": "instance",
                        "identity": "button.primary",
                    }
                ],
            },
            "project": {},
        }
        attestation["runnerEvidence"] = runner
        attestation["runnerEvidenceDigest"] = sha256_digest(runner)
        assessment = build_judgment_assessment(
            run_pin=pin,
            rule_snapshot=snapshot,
            analysis_attestation=attestation,
            audit_result=audit,
            candidate_results=[conflict_candidate()],
        )
        component = next(
            item for item in assessment["instances"] if item["ruleId"] == "rule.component-tone"
        )
        self.assertEqual(component["target"]["kind"], "coverage")
        self.assertEqual(component["rawStatus"], "not_assessed")
        self.assertEqual(
            component["incompletenessReason"],
            "sealed_occurrence_inventory_unavailable",
        )

    def test_verified_ranged_figma_occurrences_remain_distinct(self) -> None:
        from guardian_core.judgment_assessment import build_judgment_assessment

        pin, snapshot, attestation, audit = fixture()
        snapshot["rules"].append(
            judgment_rule(
                "rule.text-tone",
                {"kind": "token", "identity": "text.body"},
            )
        )
        snapshot["rulesDigest"] = sha256_digest(snapshot["rules"])
        observations = [
            {
                "kind": "style",
                "category": "typography",
                "nodeId": "100:2",
                "field": "textStyleId",
                "identity": "text.body",
                "range": {"start": 0, "end": 5},
            },
            {
                "kind": "style",
                "category": "typography",
                "nodeId": "100:2",
                "field": "textStyleId",
                "identity": "text.body",
                "range": {"start": 5, "end": 10},
            },
        ]
        runner = {
            "schemaVersion": 1,
            "adapter": "figma",
            "adapterResult": {
                "source": {"complete": True},
                "analysis": {
                    "complete": True,
                    "assessedNodes": 1,
                    "totalNodes": 1,
                    "assessedFields": 2,
                    "totalFields": 2,
                },
                "observations": observations,
            },
            "project": {},
        }
        attestation["runnerEvidence"] = runner
        attestation["runnerEvidenceDigest"] = sha256_digest(runner)
        with patch(
            "guardian_core.judgment_assessment.verify_analysis_attestation",
            create=True,
            return_value=attestation,
        ) as verifier:
            assessment = build_judgment_assessment(
                run_pin=pin,
                rule_snapshot=snapshot,
                analysis_attestation=attestation,
                audit_result=audit,
                candidate_results=[conflict_candidate()],
            )
        verifier.assert_called_once()
        ranged = [
            item
            for item in assessment["instances"]
            if item["ruleId"] == "rule.text-tone"
        ]
        self.assertEqual(len(ranged), 2)
        self.assertEqual(
            [item["target"]["range"] for item in ranged],
            [{"start": 0, "end": 5}, {"start": 5, "end": 10}],
        )
        self.assertEqual(len({item["target"]["targetId"] for item in ranged}), 2)

    def test_candidate_cannot_supply_authority_and_omission_is_not_assessed(self) -> None:
        from guardian_core.judgment_assessment import JudgmentAssessmentIntegrityError

        for field, value in (
            ("effectiveStatus", "allowed"),
            ("complete", True),
            ("productionReady", True),
        ):
            candidate = conflict_candidate()
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(JudgmentAssessmentIntegrityError):
                self.build([candidate])

        missing = self.build([])
        system = next(
            item for item in missing["instances"] if item["ruleId"] == "rule.system-balance"
        )
        self.assertEqual(system["rawStatus"], "not_assessed")
        self.assertEqual(system["incompletenessReason"], "candidate_result_unavailable")

    def test_gap_maps_only_to_sidecar_conflict_and_validation_recomputes(self) -> None:
        from guardian_core.judgment_assessment import (
            JudgmentAssessmentIntegrityError,
            validate_judgment_assessment,
        )

        run_pin, snapshot, attestation, audit = fixture(gap=True)
        original_ux = copy.deepcopy(attestation["uxEvaluation"])
        assessment = self.build(gap=True)
        inherited = [item for item in assessment["instances"] if item["source"] == "inherited_ux"]
        self.assertTrue(any(item["rawStatus"] == "conflict" for item in inherited))
        self.assertEqual(attestation["uxEvaluation"], original_ux)
        self.assertTrue(any(check["status"] == "gap" for check in original_ux["checks"]))
        self.assertEqual(
            validate_judgment_assessment(
                assessment,
                run_pin=run_pin,
                rule_snapshot=snapshot,
                analysis_attestation=attestation,
                audit_result=audit,
            ),
            assessment,
        )
        tampered = copy.deepcopy(assessment)
        tampered["complete"] = True
        with self.assertRaises(JudgmentAssessmentIntegrityError):
            validate_judgment_assessment(
                tampered,
                run_pin=run_pin,
                rule_snapshot=snapshot,
                analysis_attestation=attestation,
                audit_result=audit,
            )

    def test_positive_report_still_requires_an_active_exact_decision(self) -> None:
        from guardian_core.judgment_assessment import (
            build_judgment_assessment,
            derive_effective_judgment,
        )

        pin, snapshot, attestation, audit = fixture()
        snapshot["rules"] = [snapshot["rules"][0]]
        snapshot["rulesDigest"] = sha256_digest(snapshot["rules"])
        allowed_candidate = {
            "ruleId": "rule.system-balance",
            "targetId": None,
            "status": "allowed",
            "incompletenessReason": None,
            "findings": [],
        }
        assessment = build_judgment_assessment(
            run_pin=pin,
            rule_snapshot=snapshot,
            analysis_attestation=attestation,
            audit_result=audit,
            candidate_results=[allowed_candidate],
        )
        self.assertEqual(assessment["rawStatus"], "allowed")
        self.assertTrue(assessment["complete"])
        lane = {
            "schemaVersion": 1,
            "status": "not_assessed",
            "provider": None,
            "attestation": None,
        }
        pending = derive_effective_judgment(
            assessment,
            None,
            enforcement_authority_lane=lane,
        )
        self.assertEqual(pending["effectiveStatus"], "not_assessed")
        approved = derive_effective_judgment(
            assessment,
            {
                "active": True,
                "assessmentDigest": sha256_digest(assessment),
                "selectedFindingIds": [],
            },
            enforcement_authority_lane=lane,
        )
        self.assertEqual(approved["effectiveStatus"], "allowed")
        self.assertFalse(approved["productionReady"])

    def test_effective_projection_preserves_raw_findings_and_labels_exception(self) -> None:
        from guardian_core.judgment_assessment import (
            JudgmentAssessmentIntegrityError,
            derive_effective_judgment,
        )

        assessment = self.build()
        conflict = next(item for item in assessment["instances"] if item["rawStatus"] == "conflict")
        finding_id = conflict["findings"][0]["findingId"]
        projection = derive_effective_judgment(
            assessment,
            {
                "active": True,
                "assessmentDigest": sha256_digest(assessment),
                "selectedFindingIds": [finding_id],
            },
            enforcement_authority_lane={
                "schemaVersion": 1,
                "status": "not_assessed",
                "provider": None,
                "attestation": None,
            },
        )
        projected = next(
            item for item in projection["instances"] if item["instanceId"] == conflict["instanceId"]
        )
        self.assertEqual(projected["findings"], conflict["findings"])
        self.assertEqual(projected["effectiveStatus"], "allowed")
        self.assertEqual(
            projected["appliedExceptions"][0]["label"],
            "Passed through a user-approved exception",
        )
        self.assertFalse(projection["productionReady"])
        not_assessed = next(
            item for item in assessment["instances"] if item["rawStatus"] == "not_assessed"
        )
        with self.assertRaises(JudgmentAssessmentIntegrityError):
            derive_effective_judgment(
                assessment,
                {
                    "active": True,
                    "assessmentDigest": sha256_digest(assessment),
                    "selectedFindingIds": [not_assessed["instanceId"]],
                },
                enforcement_authority_lane={
                    "schemaVersion": 1,
                    "status": "not_assessed",
                    "provider": None,
                    "attestation": None,
                },
            )

    def test_v2_attestation_projection_still_binds_complete_v2_audit(self) -> None:
        from guardian_core.judgment_assessment import (
            JudgmentAssessmentIntegrityError,
            build_judgment_assessment,
            validate_judgment_assessment,
        )

        pin, snapshot, attestation, audit = fixture()
        assessment = build_judgment_assessment(
            run_pin=pin,
            rule_snapshot=snapshot,
            analysis_attestation=attestation,
            audit_result=audit,
            candidate_results=[conflict_candidate()],
        )
        inherited_projection = copy.deepcopy(audit)
        inherited_projection["schemaVersion"] = 1
        inherited_projection.pop("usageRulesLane")
        self.assertEqual(
            attestation["auditResultDigest"],
            sha256_digest(inherited_projection),
        )
        self.assertEqual(
            assessment["bindings"]["auditResultDigest"],
            sha256_digest(audit),
        )

        tampered = copy.deepcopy(audit)
        tampered["usageRulesLane"]["status"] = "not_assessed"
        with self.assertRaisesRegex(
            JudgmentAssessmentIntegrityError,
            "Assessment differs from recomputation",
        ):
            validate_judgment_assessment(
                assessment,
                run_pin=pin,
                rule_snapshot=snapshot,
                analysis_attestation=attestation,
                audit_result=tampered,
            )


class JudgmentSchemaTest(unittest.TestCase):
    def schema(self, name: str) -> dict:
        return json.loads(
            (Path(__file__).resolve().parents[1] / "schemas" / name).read_text(encoding="utf-8")
        )

    def test_assessment_and_projection_schemas_are_strict_and_bounded(self) -> None:
        for name in (
            "judgment-assessment.schema.json",
            "judgment-effective-projection.schema.json",
        ):
            schema = self.schema(name)
            Draft202012Validator.check_schema(schema)
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(schema["properties"]["schemaVersion"], {"const": 1})

        assessment = JudgmentAssessmentTest().build()
        validator = Draft202012Validator(self.schema("judgment-assessment.schema.json"))
        validator.validate(assessment)
        uppercase = copy.deepcopy(assessment)
        uppercase["bindings"]["runPinDigest"] = "A" * 64
        with self.assertRaises(ValidationError):
            validator.validate(uppercase)
        extra = copy.deepcopy(assessment)
        extra["instances"][0]["effectiveStatus"] = "allowed"
        with self.assertRaises(ValidationError):
            validator.validate(extra)


if __name__ == "__main__":
    unittest.main()
