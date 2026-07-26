from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.test_cli_figma_dsg017 import (
    figma_observation,
    provision_figma_run,
    ux_evidence,
)
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical


class FigmaUxTargetBindingCliTest(unittest.TestCase):
    def test_figma_audit_rejects_an_unrelated_ux_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            pin, snapshot, project = provision_figma_run(
                home, root, run_id="run-figma-unrelated-ux"
            )
            request_path = root / "audit.json"
            write_canonical(
                request_path,
                {
                    "schemaVersion": 2,
                    "adapter": "figma",
                    "projectRoot": str(project),
                    "resolutions": [],
                    "uxEvidence": ux_evidence(),
                    "adapterEvidence": figma_observation(pin, snapshot),
                },
            )

            code, error = invoke(
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

            self.assertEqual(code, 2)
            self.assertEqual(error["status"], "invalid")
            self.assertIn("exact audited document roots", error["message"])


if __name__ == "__main__":
    unittest.main()
