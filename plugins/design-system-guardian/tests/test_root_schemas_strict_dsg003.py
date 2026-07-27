import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_E = "e" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)
STATUSES = (
    "allowed",
    "missing",
    "ambiguous",
    "conflict",
    "invalid",
    "unsupported",
    "stale",
    "source_unavailable",
    "source_incomplete",
    "not_assessed",
)


def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def validator(name: str) -> Draft202012Validator:
    schemas = {
        candidate["$id"]: candidate
        for path in SCHEMA_ROOT.glob("*.schema.json")
        for candidate in [json.loads(path.read_text(encoding="utf-8"))]
    }
    schema = load_schema(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        resolver=RefResolver.from_schema(schema, store=schemas),
    )
def project_evidence() -> dict:
    return {
        "canonicalRoot": "C:\\product",
        "rootIdentity": HEX_A,
        "gitCommit": "a" * 40,
        "assessedTreeDigest": HEX_B,
        "analysisInputsDigest": HEX_C,
    }


def enforcement_authority_lane() -> dict:
    return {
        "schemaVersion": 1,
        "status": "not_assessed",
        "provider": None,
        "attestation": None,
    }



def coverage() -> dict:
    return {
        "schemaVersion": 1,
        "adapter": "flutter",
        "supported": True,
        "configDigest": HEX_E,
        "complete": True,
        "status": "allowed",
        "categories": {
            category: {"status": "allowed", "assessedItems": 1, "totalItems": 1}
            for category in CATEGORIES
        },
        "assessedFiles": 2,
        "totalFiles": 2,
    }


def allowed_resolution() -> dict:
    return {
        "schemaVersion": 1,
        "status": "allowed",
        "profileId": "example-company",
        "snapshotId": HEX_D,
        "request": {
            "kind": "token",
            "identity": "color.action.primary",
            "tokenType": "color",
            "resolverContext": {"theme": "light"},
        },
        "selectedIdentity": "color.action.primary",
        "evidence": {
            "match": "exact_identity",
            "policyDigest": HEX_A,
            "sourceState": "fresh",
            "degraded": False,
            "provenance": {"published": True},
            "tokenType": "color",
            "resolverContext": {"theme": "light"},
        },
        "sentinel": None,
    }


def audit_result() -> dict:
    return {
        "schemaVersion": 1,
        "runId": "run-schema",
        "profileId": "example-company",
        "snapshotId": HEX_D,
        "policyDigest": HEX_A,
        "analysisAttestationDigest": HEX_E,
        "projectEvidence": project_evidence(),
        "enforcementAuthorityLane": enforcement_authority_lane(),
        "designSystemLane": {
            "status": "allowed",
            "sourceCutDigest": HEX_C,
            "violations": [],
            "gaps": [],
            "sentinelCount": 0,
            "resolutionSummary": {status: (1 if status == "allowed" else 0) for status in STATUSES},
        },
        "uxAccessibilityLane": {
            "status": "allowed",
            "checks": [
                {
                    "checkId": "ux-hierarchy",
                    "area": "hierarchy",
                    "status": "allowed",
                    "message": "Hierarchy assessed.",
                    "evidence": {"review": "complete"},
                }
            ],
        },
        "coverage": coverage(),
        "resolutions": [allowed_resolution()],
        "productionReady": True,
    }


def source_cut() -> dict:
    return {
        "figmaFiles": [{"fileKey": "figma-brand", "version": "42"}],
        "catalogDigest": HEX_B,
        "codeConnectParseDigest": HEX_C,
        "repositoryCommit": "abc1234",
        "componentCatalogBuild": "build-7",
    }


class StrictRootSchemasTest(unittest.TestCase):
    def test_all_root_schemas_are_valid_strict_draft_2020_12(self) -> None:
        expected = {
            "audit-result.schema.json",
            "audit-result-v2.schema.json",
            "evaluator-authorization-pointer.schema.json",
            "evaluator-authorization-record.schema.json",
            "evaluator-upgrade-permission.schema.json",
            "post-run-assessment.schema.json",
            "post-run-assessment-v2.schema.json",
            "build-plan.schema.json",
            "coverage.schema.json",
            "profile.schema.json",
            "resolution.schema.json",
            "rule-activation-permission.schema.json",
            "rule-activation-snapshot.schema.json",
            "rule.schema.json",
            "rules-list.schema.json",
            "rules-validation-report.schema.json",
            "run-manifest.schema.json",
            "run-manifest-v2.schema.json",
            "usage-rules-evidence.schema.json",
            "judgment-assessment.schema.json",
            "judgment-effective-projection.schema.json",
            "judgment-decision-permission.schema.json",
            "judgment-history-record.schema.json",
            "judgment-history-head.schema.json",
            "snapshot.schema.json",
        }
        self.assertEqual({path.name for path in SCHEMA_ROOT.glob("*.schema.json")}, expected)
        for name in expected:
            schema = load_schema(name)
            Draft202012Validator.check_schema(schema)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(schema.get("additionalProperties", True), name)

    def test_runtime_shaped_audit_coverage_and_resolution_validate(self) -> None:
        validator("coverage.schema.json").validate(coverage())
        validator("resolution.schema.json").validate(allowed_resolution())
        validator("audit-result.schema.json").validate(audit_result())

    def test_nested_coverage_lane_and_request_drift_are_rejected(self) -> None:
        forged_coverage = coverage()
        forged_coverage["categories"]["colors"]["rawFallback"] = "#0055FF"
        with self.assertRaises(ValidationError):
            validator("coverage.schema.json").validate(forged_coverage)

        missing_category = coverage()
        del missing_category["categories"]["motion"]
        with self.assertRaises(ValidationError):
            validator("coverage.schema.json").validate(missing_category)

        raw_request = allowed_resolution()
        raw_request["request"]["rawValue"] = "#0055FF"
        with self.assertRaises(ValidationError):
            validator("resolution.schema.json").validate(raw_request)

        wrong_sentinel = allowed_resolution()
        wrong_sentinel["sentinel"] = {"label": "looks missing"}
        with self.assertRaises(ValidationError):
            validator("resolution.schema.json").validate(wrong_sentinel)

    def test_audit_lanes_and_resolution_summary_are_not_open_objects(self) -> None:
        extra_lane = audit_result()
        extra_lane["designSystemLane"]["nearestColor"] = "blue.500"
        with self.assertRaises(ValidationError):
            validator("audit-result.schema.json").validate(extra_lane)

        missing_status_count = audit_result()
        del missing_status_count["designSystemLane"]["resolutionSummary"]["source_incomplete"]
        with self.assertRaises(ValidationError):
            validator("audit-result.schema.json").validate(missing_status_count)

        wrong_diagnostic_lane = audit_result()
        wrong_diagnostic_lane["designSystemLane"]["violations"] = [
            {
                "diagnosticId": "gap-in-wrong-lane",
                "category": "colors",
                "kind": "design_system_gap",
                "message": "Wrong lane.",
                "evidence": {},
            }
        ]
        with self.assertRaises(ValidationError):
            validator("audit-result.schema.json").validate(wrong_diagnostic_lane)

    def test_build_plan_uses_text_decisions_allowed_resolutions_and_fixed_sentinels(self) -> None:
        plan = {
            "schemaVersion": 1,
            "runId": "run-schema",
            "profileId": "example-company",
            "snapshotId": HEX_D,
            "policyDigest": HEX_A,
            "uxDecision": {
                "hierarchy": ["Primary action follows approved content hierarchy."],
                "states": ["Loading and error states assessed."],
                "accessibility": ["Focus order assessed."],
                "componentIntent": ["Approved primary button expresses submit intent."],
            },
            "selections": [allowed_resolution()],
            "sentinels": [],
            "productionReady": True,
        }
        validator("build-plan.schema.json").validate(plan)

        unbound_selection = copy.deepcopy(plan)
        unbound_selection["selections"][0]["status"] = "conflict"
        unbound_selection["selections"][0]["selectedIdentity"] = None
        with self.assertRaises(ValidationError):
            validator("build-plan.schema.json").validate(unbound_selection)

        invented_decision_shape = copy.deepcopy(plan)
        invented_decision_shape["uxDecision"]["hierarchy"] = [{"token": "spacing.8"}]
        with self.assertRaises(ValidationError):
            validator("build-plan.schema.json").validate(invented_decision_shape)

    def test_run_manifest_seals_exact_source_cut_inputs_and_outputs(self) -> None:
        manifest = {
            "schemaVersion": 1,
            "runId": "run-schema",
            "profileId": "example-company",
            "snapshotId": HEX_D,
            "policyDigest": HEX_A,
            "command": "finalize",
            "startedAt": "2026-07-15T12:00:00Z",
            "completedAt": "2026-07-15T12:00:01Z",
            "sourceCut": source_cut(),
            "projectEvidence": project_evidence(),
            "enforcementAuthorityLane": enforcement_authority_lane(),
            "inputs": [
                {"artifactType": "run-pin", "digest": HEX_B},
                {"artifactType": "audit-result", "digest": HEX_C},
            ],
            "outputs": [
                {"artifactType": "audit-result", "path": "profiles/example-company/runs/run-schema/audit-result.json", "payloadDigest": HEX_A},
                {"artifactType": "coverage", "path": "profiles/example-company/runs/run-schema/coverage.json", "payloadDigest": HEX_B},
                {"artifactType": "readable-report", "path": "profiles/example-company/runs/run-schema/report.md", "payloadDigest": HEX_C},
            ],
            "exitCode": 4,
            "productionReady": False,
        }
        validator("run-manifest.schema.json").validate(manifest)

        latest = copy.deepcopy(manifest)
        latest["sourceCut"]["latest"] = True
        with self.assertRaises(ValidationError):
            validator("run-manifest.schema.json").validate(latest)

        absolute_output = copy.deepcopy(manifest)
        absolute_output["outputs"][0]["path"] = "C:/unsealed/audit.json"
        with self.assertRaises(ValidationError):
            validator("run-manifest.schema.json").validate(absolute_output)


if __name__ == "__main__":
    unittest.main()
