import copy
import inspect
import tempfile
import unittest
from pathlib import Path

from tests.test_finalize_artifacts_dsg003 import clean_audit, provision_run
from tests.test_profile_snapshot import NOW


class EnforcementAuthorityLaneTest(unittest.TestCase):
    def test_v01_audit_has_exact_fail_closed_authority_lane(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-authority-lane")
            evaluation = clean_audit(pin)

            self.assertIn("enforcementAuthorityLane", evaluation.result)
            self.assertEqual(
                evaluation.result["enforcementAuthorityLane"],
                {
                    "schemaVersion": 1,
                    "status": "not_assessed",
                    "provider": None,
                    "attestation": None,
                },
            )
            self.assertEqual(int(evaluation.exit_code), 4)
            self.assertFalse(evaluation.result["productionReady"])

    def test_local_seal_and_forged_allowed_lane_cannot_pass_clean_verifier(self) -> None:
        from guardian_core.audit import AuditIntegrityError, derive_audit_exit_code
        from guardian_core.finalize import FinalizationError, _finalize_run_at
        from guardian_core.preflight import load_run_pin
        from guardian_core.run_artifacts import seal_run_artifact, verify_run_artifact

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-forged-authority")
            forged = copy.deepcopy(clean_audit(pin).result)
            forged["enforcementAuthorityLane"] = {
                "schemaVersion": 1,
                "status": "allowed",
                "provider": "caller-local",
                "attestation": "a" * 64,
            }
            forged["productionReady"] = True

            envelope = seal_run_artifact(
                home,
                artifact_type="audit-result",
                profile_id="example-company",
                run_id="run-forged-authority",
                payload=forged,
            )
            self.assertEqual(verify_run_artifact(home, envelope), forged)
            with self.assertRaises(AuditIntegrityError):
                derive_audit_exit_code(forged)

            context = load_run_pin(
                home,
                profile_id="example-company",
                run_id="run-forged-authority",
            )
            timestamp = NOW.isoformat().replace("+00:00", "Z")
            with self.assertRaises(FinalizationError):
                _finalize_run_at(
                    home,
                    profile_id="example-company",
                    run_id="run-forged-authority",
                    audit_result=forged,
                    build_plan=None,
                    started_at=timestamp,
                    completed_at=timestamp,
                )
            self.assertEqual(context["pin"]["projectBinding"], pin["projectBinding"])

    def test_authority_stub_has_no_runtime_provider_injection_surface(self) -> None:
        import guardian_core.enforcement_authority as authority

        self.assertEqual(inspect.signature(authority.enforcement_authority_lane).parameters, {})
        source = inspect.getsource(authority)
        self.assertNotIn("os.environ", source)
        self.assertNotIn("shutil.which", source)
        self.assertNotIn("entry_points", source)


if __name__ == "__main__":
    unittest.main()
