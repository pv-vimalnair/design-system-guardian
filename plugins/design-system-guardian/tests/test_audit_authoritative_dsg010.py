import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.flutter_runner_test_support import (
    create_minimal_flutter_project,
    runner_side_effect,
)
from tests.test_audit_dsg003 import allowed_ux_check, complete_adapter, sample_pin
from tests.test_audit_dsg003 import sample_project_evidence, sample_snapshot
from tests.test_cli_lifecycle_dsg003 import audit_request, invoke, write_canonical
from tests.test_finalize_artifacts_dsg003 import clean_audit, provision_run


class AuthoritativeAuditTest(unittest.TestCase):
    def test_caller_allowed_claim_for_absent_identity_is_resolved_as_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_run(home, run_id="run-forged-resolution")
            project = create_minimal_flutter_project(root)
            project = Path(pin["projectBinding"]["canonicalRoot"])
            request = audit_request(pin, project)
            request["resolutions"] = [
                {
                    "schemaVersion": 1,
                    "status": "allowed",
                    "profileId": pin["profileId"],
                    "snapshotId": pin["snapshotId"],
                    "request": {
                        "requestId": "forged-absent-icon",
                        "kind": "icon",
                        "identity": "icon.not-in-catalog",
                    },
                    "selectedIdentity": "icon.not-in-catalog",
                    "evidence": {"policyDigest": pin["policyDigest"]},
                    "sentinel": None,
                }
            ]
            request_path = root / "audit-request.json"
            write_canonical(request_path, request)

            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=runner_side_effect(),
            ):
                code, result = invoke(
                    home,
                    [
                        "audit",
                        "--profile",
                        pin["profileId"],
                        "--run-id",
                        pin["runId"],
                        "--input",
                        str(request_path),
                    ],
                )

            self.assertNotEqual(code, 0)
            self.assertFalse(result["productionReady"])
            self.assertEqual(result["resolutions"][0]["status"], "missing")
            self.assertIsNotNone(result["resolutions"][0]["sentinel"])
            self.assertEqual(result["designSystemLane"]["resolutionSummary"]["allowed"], 0)
            self.assertEqual(result["designSystemLane"]["resolutionSummary"]["missing"], 1)

    def test_caller_allowed_ux_assertion_is_forced_to_not_assessed(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.contracts import ExitCode

        evaluation = evaluate_audit(
            run_pin=sample_pin(),
            adapter_result=complete_adapter(),
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )

        self.assertEqual(
            evaluation.exit_code,
            ExitCode.UNSUPPORTED_ADAPTER_OR_INCOMPLETE_COVERAGE,
        )
        self.assertFalse(evaluation.result["productionReady"])
        self.assertEqual(evaluation.result["uxAccessibilityLane"]["status"], "not_assessed")
        self.assertEqual(
            evaluation.result["uxAccessibilityLane"]["checks"][0]["evidence"]["reason"],
            "trusted_ux_evaluator_unavailable",
        )

    def test_finalize_rejects_forged_resolution_even_when_audit_shape_is_consistent(self) -> None:
        from guardian_core.preflight import load_run_pin
        from tests.test_profile_snapshot import NOW

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_run(home, run_id="run-finalize-forged-resolution")
            audit = clean_audit(pin).result
            forged = {
                "schemaVersion": 1,
                "status": "allowed",
                "profileId": pin["profileId"],
                "snapshotId": pin["snapshotId"],
                "request": {
                    "requestId": "forged-final-icon",
                    "kind": "icon",
                    "identity": "icon.not-in-catalog",
                },
                "selectedIdentity": "icon.not-in-catalog",
                "evidence": {"policyDigest": pin["policyDigest"]},
                "sentinel": None,
            }
            audit["resolutions"] = [forged]
            audit["designSystemLane"]["resolutionSummary"]["allowed"] = 1
            audit_path = root / "forged-audit.json"
            write_canonical(audit_path, audit)

            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                code, result = invoke(
                    home,
                    [
                        "finalize",
                        "--profile",
                        pin["profileId"],
                        "--run-id",
                        pin["runId"],
                        "--audit-result",
                        str(audit_path),
                    ],
                )

            self.assertEqual(code, 2)
            self.assertIn("authoritative", result["message"].lower())


if __name__ == "__main__":
    unittest.main()
