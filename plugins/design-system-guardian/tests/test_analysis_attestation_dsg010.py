import copy
import unittest
from unittest.mock import patch

from tests.test_audit_dsg003 import sample_project_binding


class AnalysisAttestationTest(unittest.TestCase):
    def pin(self) -> dict:
        return {
            "schemaVersion": 1,
            "runId": "run-attested",
            "profileId": "example-company",
            "snapshotId": "b" * 64,
            "policyDigest": "a" * 64,
            "sourceCut": {"catalog": "v1"},
            "projectBinding": sample_project_binding(),
        }

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
                "binding": {
                    "profileId": pin["profileId"],
                    "snapshotId": pin["snapshotId"],
                    "policyDigest": pin["policyDigest"],
                    "sourceCutDigest": "e" * 64,
                    "configDigest": "f" * 64,
                }
            },
        }

    def audit(self, runner: dict) -> dict:
        from guardian_core.canonical import sha256_digest

        pin = self.pin()
        return {
            "schemaVersion": 1,
            "runId": pin["runId"],
            "profileId": pin["profileId"],
            "snapshotId": pin["snapshotId"],
            "policyDigest": pin["policyDigest"],
            "projectEvidence": {key: runner["project"][key] for key in ("canonicalRoot", "rootIdentity", "gitCommit", "assessedTreeDigest", "analysisInputsDigest")},
            "analysisAttestationDigest": sha256_digest(runner),
            "productionReady": False,
        }

    def test_exact_runner_and_audit_binding_verifies(self) -> None:
        from guardian_core.audit_attestation import (
            build_analysis_attestation,
            verify_analysis_attestation,
        )

        runner = self.runner()
        audit = self.audit(runner)
        payload = build_analysis_attestation(
            run_pin=self.pin(),
            config_digest="f" * 64,
            runner_evidence=runner,
            audit_result=audit,
        )
        with patch(
            "guardian_core.audit_attestation.verify_flutter_project_evidence",
            return_value=runner["project"],
        ) as project_verifier:
            self.assertEqual(
                verify_analysis_attestation(
                    payload,
                    run_pin=self.pin(),
                    config_digest="f" * 64,
                    audit_result=audit,
                ),
                payload,
            )
        project_verifier.assert_called_once_with(runner)

    def test_tampered_audit_or_runner_is_rejected(self) -> None:
        from guardian_core.audit_attestation import (
            AnalysisAttestationIntegrityError,
            build_analysis_attestation,
            verify_analysis_attestation,
        )

        runner = self.runner()
        audit = self.audit(runner)
        payload = build_analysis_attestation(
            run_pin=self.pin(),
            config_digest="f" * 64,
            runner_evidence=runner,
            audit_result=audit,
        )
        tampered_audit = copy.deepcopy(audit)
        tampered_audit["productionReady"] = True
        with self.assertRaises(AnalysisAttestationIntegrityError):
            verify_analysis_attestation(
                payload,
                run_pin=self.pin(),
                config_digest="f" * 64,
                audit_result=tampered_audit,
            )

        tampered_runner = copy.deepcopy(payload)
        tampered_runner["runnerEvidence"]["analyzer"]["tool"] = "forged"
        with self.assertRaises(AnalysisAttestationIntegrityError):
            verify_analysis_attestation(
                tampered_runner,
                run_pin=self.pin(),
                config_digest="f" * 64,
                audit_result=audit,
            )

    def test_replayed_source_manifest_failure_propagates(self) -> None:
        from guardian_core.audit_attestation import build_analysis_attestation, verify_analysis_attestation
        from guardian_core.flutter_runner import FlutterRunnerIntegrityError

        runner = self.runner()
        audit = self.audit(runner)
        payload = build_analysis_attestation(
            run_pin=self.pin(), config_digest="f" * 64,
            runner_evidence=runner, audit_result=audit,
        )
        with patch(
            "guardian_core.audit_attestation.verify_flutter_project_evidence",
            side_effect=FlutterRunnerIntegrityError("source changed"),
        ), self.assertRaisesRegex(FlutterRunnerIntegrityError, "source changed"):
            verify_analysis_attestation(
                payload,
                run_pin=self.pin(), config_digest="f" * 64,
                audit_result=audit,
            )


if __name__ == "__main__":
    unittest.main()
