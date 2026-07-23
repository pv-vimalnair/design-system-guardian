import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_audit_dsg003 import allowed_ux_check, sample_pin
from tests.test_audit_dsg003 import sample_project_evidence, sample_snapshot
from tests.test_finalize_artifacts_dsg003 import NOW, clean_audit, provision_run
from tests.test_flutter_adapter_normalization_dsg003 import clean_flutter_result, flutter_config


class AuditConfigDigestProvenanceTest(unittest.TestCase):
    def test_normalized_and_audit_coverage_preserve_exact_config_digest(self) -> None:
        from guardian_core.audit import evaluate_audit
        from guardian_core.flutter_adapter import normalize_flutter_adapter_result

        pin = sample_pin()
        config = flutter_config(pin)
        normalized = normalize_flutter_adapter_result(
            clean_flutter_result(pin),
            adapter_config=config,
            run_pin=pin,
        )
        self.assertEqual(normalized["configDigest"], config["configDigest"])
        result = evaluate_audit(
            run_pin=pin,
            adapter_result=normalized,
            resolutions=[],
            ux_checks=[allowed_ux_check()],
            project_evidence=sample_project_evidence(),
            verified_snapshot=sample_snapshot(),
        )
        self.assertEqual(result.result["coverage"]["configDigest"], config["configDigest"])

    def test_finalize_rejects_coverage_bound_to_a_different_config(self) -> None:
        from guardian_core.finalize import FinalizationError, _finalize_run_at

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-config-digest-final")
            audit = copy.deepcopy(clean_audit(pin).result)
            audit["coverage"]["configDigest"] = "f" * 64
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                with self.assertRaisesRegex(FinalizationError, "adapter config"):
                    _finalize_run_at(
                        home,
                        profile_id="example-company",
                        run_id="run-config-digest-final",
                        audit_result=audit,
                        build_plan=None,
                        started_at="2026-07-15T12:00:00Z",
                        completed_at="2026-07-15T12:00:01Z",
                    )


if __name__ == "__main__":
    unittest.main()
