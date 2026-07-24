import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from guardian_core.canonical import canonical_json_text
from guardian_core.post_run import (
    PostRunAssessmentIntegrityError,
    build_post_run_assessment,
)


ROOT = Path(__file__).resolve().parents[1]
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64
RESOLUTION_STATUSES = (
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


def audit_result() -> dict:
    return {
        "schemaVersion": 1,
        "runId": "run-post-1",
        "profileId": "example-company",
        "snapshotId": HEX_D,
        "policyDigest": HEX_A,
        "analysisAttestationDigest": HEX_B,
        "projectEvidence": {
            "canonicalRoot": "C:\\private-product\\mobile",
            "rootIdentity": HEX_C,
            "gitCommit": "f" * 40,
            "assessedTreeDigest": HEX_C,
            "analysisInputsDigest": HEX_E,
        },
        "enforcementAuthorityLane": {
            "schemaVersion": 1,
            "status": "not_assessed",
            "provider": None,
            "attestation": None,
        },
        "designSystemLane": {
            "status": "invalid",
            "sourceCutDigest": HEX_E,
            "violations": [
                {
                    "diagnosticId": "raw-color",
                    "category": "colors",
                    "kind": "violation",
                    "message": "Private diagnostic must not escape.",
                    "evidence": {"path": "C:\\private-product\\mobile\\lib\\app.dart"},
                }
            ],
            "gaps": [
                {
                    "diagnosticId": "missing-icon",
                    "category": "icons",
                    "kind": "design_system_gap",
                    "message": "Private catalog details must not escape.",
                    "evidence": {"catalogPayload": {"identity": "icon.private"}},
                }
            ],
            "sentinelCount": 1,
            "resolutionSummary": {
                status: (2 if status == "allowed" else 1 if status in {"missing", "unsupported"} else 0)
                for status in RESOLUTION_STATUSES
            },
        },
        "uxAccessibilityLane": {
            "status": "not_assessed",
            "checks": [
                {
                    "checkId": "ux-private",
                    "area": "hierarchy",
                    "status": "not_assessed",
                    "message": "Private prompt output must not escape.",
                    "evidence": {"rawOutput": "secret"},
                }
            ],
        },
        "coverage": {
            "status": "unsupported",
        },
        "resolutions": [],
        "productionReady": False,
    }


def run_manifest() -> dict:
    return {
        "schemaVersion": 1,
        "runId": "run-post-1",
        "profileId": "example-company",
        "snapshotId": HEX_D,
        "policyDigest": HEX_A,
        "exitCode": 2,
        "productionReady": False,
    }


class PostRunAssessmentTest(unittest.TestCase):
    def test_builds_deterministic_code_and_count_only_assessment(self) -> None:
        audit = audit_result()
        manifest = run_manifest()

        assessment = build_post_run_assessment(
            audit_result=audit,
            run_manifest=manifest,
            run_manifest_digest=HEX_A,
            runtime_version="0.3.0",
        )

        self.assertEqual(
            assessment,
            {
                "schemaVersion": 1,
                "runId": "run-post-1",
                "profileId": "example-company",
                "snapshotId": HEX_D,
                "policyDigest": HEX_A,
                "runtimeVersion": "0.3.0",
                "evidenceDigests": {
                    "runManifest": HEX_A,
                    "analysisAttestation": HEX_B,
                    "sourceCut": HEX_E,
                    "assessedTree": HEX_C,
                    "analysisInputs": HEX_E,
                },
                "statuses": {
                    "run": "incomplete",
                    "designSystem": "invalid",
                    "uxAccessibility": "not_assessed",
                    "coverage": "unsupported",
                    "enforcementAuthority": "not_assessed",
                },
                "counts": {
                    "violations": 1,
                    "designSystemGaps": 1,
                    "sentinels": 1,
                    "allowedResolutions": 2,
                    "nonAllowedResolutions": 2,
                    "assessedUxChecks": 0,
                    "unassessedUxChecks": 1,
                },
                "reasonCodes": [
                    {"reasonCode": "design_system_gap", "attribution": "design_system", "count": 1},
                    {"reasonCode": "design_system_identity_missing", "attribution": "design_system", "count": 1},
                    {"reasonCode": "design_system_violation", "attribution": "project_implementation", "count": 1},
                    {"reasonCode": "enforcement_not_assessed", "attribution": "capability_candidate", "count": 1},
                    {"reasonCode": "resolution_missing", "attribution": "design_system", "count": 1},
                    {"reasonCode": "resolution_unsupported", "attribution": "capability_candidate", "count": 1},
                    {"reasonCode": "unsupported_adapter", "attribution": "capability_candidate", "count": 1},
                    {"reasonCode": "ux_not_assessed", "attribution": "capability_candidate", "count": 1},
                ],
                "evolutionHandoff": {
                    "status": "permission_required",
                    "target": "plugin-evolution-manager",
                    "reviewRecommended": True,
                },
                "sourceMutationPerformed": False,
            },
        )
        self.assertEqual(
            assessment,
            build_post_run_assessment(
                audit_result=copy.deepcopy(audit),
                run_manifest=copy.deepcopy(manifest),
                run_manifest_digest=HEX_A,
                runtime_version="0.3.0",
            ),
        )
        text = canonical_json_text(assessment)
        self.assertEqual(assessment["evolutionHandoff"]["status"], "permission_required")
        self.assertNotIn("message", text)
        for private_value in ("private-product", "icon.private", "rawOutput", "prompt", "secret"):
            self.assertNotIn(private_value, text)

    def test_schema_accepts_exact_assessment_and_rejects_extra_fields(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "post-run-assessment.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        assessment = build_post_run_assessment(
            audit_result=audit_result(),
            run_manifest=run_manifest(),
            run_manifest_digest=HEX_A,
            runtime_version="0.3.0",
        )
        validator.validate(assessment)

        extra_root = copy.deepcopy(assessment)
        extra_root["rawOutput"] = "forbidden"
        with self.assertRaises(ValidationError):
            validator.validate(extra_root)

        extra_handoff = copy.deepcopy(assessment)
        extra_handoff["evolutionHandoff"]["message"] = "forbidden"
        with self.assertRaises(ValidationError):
            validator.validate(extra_handoff)

    def test_rejects_mismatched_identity_and_malformed_digests(self) -> None:
        manifest = run_manifest()
        manifest["profileId"] = "another-company"
        with self.assertRaises(PostRunAssessmentIntegrityError):
            build_post_run_assessment(
                audit_result=audit_result(),
                run_manifest=manifest,
                run_manifest_digest=HEX_A,
                runtime_version="0.3.0",
            )
        with self.assertRaises(PostRunAssessmentIntegrityError):
            build_post_run_assessment(
                audit_result=audit_result(),
                run_manifest=run_manifest(),
                run_manifest_digest="not-a-digest",
                runtime_version="0.3.0",
            )

    def test_runtime_and_lifecycle_enums_include_supported_artifacts(self) -> None:
        from guardian_core.run_artifacts import _ARTIFACT_TYPES

        lifecycle = json.loads(
            (ROOT / "schemas" / "lifecycle" / "sealed-run-artifact.schema.json").read_text(
                encoding="utf-8"
            )
        )
        required = {"analysis-attestation", "post-run-assessment"}
        self.assertTrue(required <= _ARTIFACT_TYPES)
        self.assertTrue(required <= set(lifecycle["properties"]["artifactType"]["enum"]))


if __name__ == "__main__":
    unittest.main()
