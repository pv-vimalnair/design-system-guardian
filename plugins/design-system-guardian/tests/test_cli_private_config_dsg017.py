from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.test_cli_figma_dsg017 import provision_figma_run
from tests.test_cli_lifecycle_dsg003 import invoke


class PrivateAdapterConfigCliTest(unittest.TestCase):
    def test_figma_config_refuses_output_outside_guardian_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            pin, _, _ = provision_figma_run(home, root, run_id="run-private-config")
            outside = root / "public-config.json"

            code, error = invoke(
                home,
                [
                    "adapter",
                    "figma",
                    "config",
                    "--profile",
                    pin["profileId"],
                    "--run-id",
                    pin["runId"],
                    "--output",
                    str(outside),
                ],
            )

            self.assertEqual(code, 2)
            self.assertEqual(error["status"], "invalid")
            self.assertIn("escapes the configured home", error["message"])
            self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
