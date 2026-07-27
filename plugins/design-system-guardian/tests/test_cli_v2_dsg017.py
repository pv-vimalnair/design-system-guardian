from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.flutter_runner_test_support import (
    prepare_contract_runner_dependencies,
    runner_side_effect,
)
from tests.test_cli_figma_dsg017 import ux_evidence
from tests.test_cli_lifecycle_dsg003 import file_state, invoke, write_canonical
from tests.test_finalize_artifacts_dsg003 import provision_run


class FlutterV2LifecycleCliTest(unittest.TestCase):
    def test_flutter_v2_uses_the_internal_final_flow_evaluator(self) -> None:
        from guardian_core.run_artifacts import read_run_artifact

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            pin = provision_run(home, run_id="run-flutter-v2")
            project = Path(pin["projectBinding"]["canonicalRoot"])
            prepare_contract_runner_dependencies(project)
            before = file_state(project)
            request_path = root / "audit-request.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 2,
                    "adapter": "flutter",
                    "projectRoot": str(project),
                    "resolutions": [],
                    "uxEvidence": ux_evidence(),
                    "adapterEvidence": None,
                },
            )

            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=runner_side_effect(),
            ):
                code, audit = invoke(
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

            self.assertEqual(code, 4)
            self.assertEqual(audit["coverage"]["adapter"], "flutter")
            self.assertEqual(audit["designSystemLane"]["status"], "allowed")
            self.assertEqual(audit["uxAccessibilityLane"]["status"], "not_assessed")
            self.assertNotIn("effectiveProjection", audit)
            self.assertNotIn("readableReport", audit)
            self.assertEqual(file_state(project), before)
            attestation = read_run_artifact(
                home,
                profile_id=pin["profileId"],
                run_id=pin["runId"],
                artifact_type="analysis-attestation",
            )["payload"]
            self.assertEqual(attestation["uxTarget"], ux_evidence()["target"])
            self.assertIn("uxEvaluationDigest", attestation)


if __name__ == "__main__":
    unittest.main()
