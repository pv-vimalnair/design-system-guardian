import copy
import unittest
from unittest.mock import patch

from tests.test_audit_dsg003 import complete_adapter, sample_project_binding


class AnalysisAttestationTest(unittest.TestCase):
    def pin(self) -> dict:
        return {
            "schemaVersion": 1,
            "runId": "run-attested",
            "profileId": "example-company",
            "snapshotId": "b" * 64,
            "policyDigest": "a" * 64,
            "sourceCut": {"catalog": "v1"},
            "sourceState": "fresh",
            "projectBinding": sample_project_binding(),
        }

    def normalized_adapter(self) -> dict:
        value = complete_adapter()
        value["sourceCut"] = copy.deepcopy(self.pin()["sourceCut"])
        value["configDigest"] = "f" * 64
        return value

    def runner(self) -> dict:
        pin = self.pin()
        project = {
            **pin["projectBinding"],
            "files": [],
            "assessedTreeDigest": "1" * 64,
            "analysisInputsDigest": "2" * 64,
        }
        return {
            "schemaVersion": 1,
            "runner": "design-system-guardian-host",
            "runnerVersion": "0.1.0",
            "project": project,
            "analyzer": {"tool": "dart"},
            "sentinelEvidenceDigest": "c" * 64,
            "runPinDigest": "d" * 64,
            "adapterResult": {
                "adapter": "flutter",
                "binding": {
                    "profileId": pin["profileId"],
                    "snapshotId": pin["snapshotId"],
                    "policyDigest": pin["policyDigest"],
                    "sourceCutDigest": "e" * 64,
                    "configDigest": "f" * 64,
                },
            },
        }

    def audit(self, runner: dict) -> dict:
        from guardian_core.audit import (
            adapter_audit_projection,
            canonical_untrusted_ux_lane,
        )
        from guardian_core.canonical import sha256_digest

        pin = self.pin()
        coverage, diagnostics = adapter_audit_projection(
            self.normalized_adapter(), pin["sourceCut"]
        )
        return {
            "schemaVersion": 1,
            "runId": pin["runId"],
            "profileId": pin["profileId"],
            "snapshotId": pin["snapshotId"],
            "policyDigest": pin["policyDigest"],
            "projectEvidence": {
                key: runner["project"][key]
                for key in (
                    "canonicalRoot",
                    "rootIdentity",
                    "gitCommit",
                    "assessedTreeDigest",
                    "analysisInputsDigest",
                )
            },
            "analysisAttestationDigest": sha256_digest(runner),
            "coverage": coverage,
            "designSystemLane": {
                "violations": [
                    item for item in diagnostics if item["kind"] == "violation"
                ],
                "gaps": [
                    item
                    for item in diagnostics
                    if item["kind"] == "design_system_gap"
                ],
            },
            "uxAccessibilityLane": canonical_untrusted_ux_lane(),
            "productionReady": False,
        }

    def build(self, runner: dict, audit: dict) -> dict:
        from guardian_core.audit_attestation import build_analysis_attestation

        with patch(
            "guardian_core.audit_attestation.normalize_flutter_adapter_result",
            return_value=self.normalized_adapter(),
        ):
            return build_analysis_attestation(
                run_pin=self.pin(),
                config_digest="f" * 64,
                runner_evidence=runner,
                audit_result=audit,
                adapter_config={},
            )

    def verify(self, payload: dict, audit: dict) -> dict:
        from guardian_core.audit_attestation import verify_analysis_attestation

        with patch(
            "guardian_core.audit_attestation.normalize_flutter_adapter_result",
            return_value=self.normalized_adapter(),
        ):
            return verify_analysis_attestation(
                payload,
                run_pin=self.pin(),
                config_digest="f" * 64,
                audit_result=audit,
                adapter_config={},
            )

    def test_exact_runner_and_audit_binding_verifies(self) -> None:
        runner = self.runner()
        audit = self.audit(runner)
        payload = self.build(runner, audit)
        with patch(
            "guardian_core.audit_attestation.verify_flutter_project_evidence",
            return_value=runner["project"],
        ) as project_verifier:
            self.assertEqual(self.verify(payload, audit), payload)
        project_verifier.assert_called_once_with(runner)

    def test_tampered_audit_or_runner_is_rejected(self) -> None:
        from guardian_core.audit_attestation import AnalysisAttestationIntegrityError

        runner = self.runner()
        audit = self.audit(runner)
        payload = self.build(runner, audit)
        tampered_audit = copy.deepcopy(audit)
        tampered_audit["productionReady"] = True
        with self.assertRaises(AnalysisAttestationIntegrityError):
            self.verify(payload, tampered_audit)

        tampered_runner = copy.deepcopy(payload)
        tampered_runner["runnerEvidence"]["analyzer"]["tool"] = "forged"
        with self.assertRaises(AnalysisAttestationIntegrityError):
            self.verify(tampered_runner, audit)

    def test_audit_coverage_and_diagnostics_must_match_normalized_runner(self) -> None:
        from guardian_core.audit_attestation import AnalysisAttestationIntegrityError

        runner = self.runner()
        audit = self.audit(runner)
        forged_coverage = copy.deepcopy(audit)
        forged_coverage["coverage"]["categories"]["colors"]["status"] = "not_assessed"
        with self.assertRaisesRegex(AnalysisAttestationIntegrityError, "coverage"):
            self.build(runner, forged_coverage)

        forged_diagnostics = copy.deepcopy(audit)
        forged_diagnostics["designSystemLane"]["violations"] = [
            {
                "diagnosticId": "forged",
                "category": "colors",
                "kind": "violation",
                "message": "forged",
                "evidence": {},
            }
        ]
        with self.assertRaisesRegex(AnalysisAttestationIntegrityError, "diagnostics"):
            self.build(runner, forged_diagnostics)

    def test_no_ux_attestation_requires_canonical_untrusted_lane(self) -> None:
        from guardian_core.audit_attestation import AnalysisAttestationIntegrityError

        runner = self.runner()
        audit = self.audit(runner)
        audit["uxAccessibilityLane"] = {"status": "allowed", "checks": []}
        with self.assertRaisesRegex(AnalysisAttestationIntegrityError, "canonical untrusted"):
            self.build(runner, audit)

    def test_replayed_source_manifest_failure_propagates(self) -> None:
        from guardian_core.flutter_runner import FlutterRunnerIntegrityError

        runner = self.runner()
        audit = self.audit(runner)
        payload = self.build(runner, audit)
        with patch(
            "guardian_core.audit_attestation.normalize_flutter_adapter_result",
            return_value=self.normalized_adapter(),
        ), patch(
            "guardian_core.audit_attestation.verify_flutter_project_evidence",
            side_effect=FlutterRunnerIntegrityError("source changed"),
        ), self.assertRaisesRegex(FlutterRunnerIntegrityError, "source changed"):
            from guardian_core.audit_attestation import verify_analysis_attestation

            verify_analysis_attestation(
                payload,
                run_pin=self.pin(),
                config_digest="f" * 64,
                audit_result=audit,
                adapter_config={},
            )


if __name__ == "__main__":
    unittest.main()