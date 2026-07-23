import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_finalize_artifacts_dsg003 import NOW, attested_audit, provision_run


class ReadableReportProvenanceTest(unittest.TestCase):
    def test_report_projects_policy_source_cut_and_adapter_config_digests(self) -> None:
        from guardian_core.finalize import finalize_run

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            pin = provision_run(home, run_id="run-report-provenance")
            audit, _ = attested_audit(home, pin, Path(directory))
            with patch("guardian_core.finalize._utc_now", return_value=NOW):
                result = finalize_run(
                    home,
                    profile_id="example-company",
                    run_id="run-report-provenance",
                    audit_result=audit,
                    build_plan=None,
                )
            report = result.artifact_paths["readable-report"].read_text(encoding="utf-8")
            self.assertIn(f"Policy: {pin['policyDigest']}", report)
            self.assertIn(
                f"Source cut: {audit['designSystemLane']['sourceCutDigest']}",
                report,
            )
            self.assertIn(f"Adapter config: {audit['coverage']['configDigest']}", report)


if __name__ == "__main__":
    unittest.main()
