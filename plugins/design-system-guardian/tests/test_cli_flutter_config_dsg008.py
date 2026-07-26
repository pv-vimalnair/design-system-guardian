import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.flutter_runner_test_support import (
    create_minimal_flutter_project,
    runner_side_effect,
)
from tests.test_audit_dsg003 import allowed_ux_check
from tests.test_cli_lifecycle_dsg003 import invoke, write_canonical
from tests.test_flutter_config_dsg008 import fully_mapped_catalog, provision_pin


class FlutterConfigCliTest(unittest.TestCase):
    def test_generated_config_is_canonical_and_accepted_by_core_audit(self) -> None:
        from guardian_core.canonical import canonical_json_bytes
        from guardian_core.cli import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            home.mkdir()
            project = create_minimal_flutter_project(root)
            pin = provision_pin(home, fully_mapped_catalog(), run_id="run-cli-config", project_root=project)
            output = home / "private" / "guardian_flutter_config.json"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with (
                patch("guardian_core.cli.default_guardian_home", return_value=home),
                patch("guardian_core.flutter_config.default_guardian_home", return_value=home),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                code = main(
                    [
                        "adapter",
                        "flutter",
                        "config",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-cli-config",
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(code, 0, stderr.getvalue())
            emitted = json.loads(stdout.getvalue())
            config = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(output.read_bytes(), canonical_json_bytes(config))
            self.assertEqual(emitted["configDigest"], config["configDigest"])
            self.assertEqual(emitted["outputPath"], str(output.absolute()))

            audit_input = root / "audit-request.json"
            write_canonical(
                audit_input,
                {
                    "schemaVersion": 1,
                    "projectRoot": str(project),
                    "resolutions": [],
                    "uxChecks": [allowed_ux_check()],
                },
            )

            with patch(
                "guardian_core.cli.run_flutter_analysis",
                side_effect=runner_side_effect(),
            ):
                audit_code, audit = invoke(
                    home,
                    [
                        "audit",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "run-cli-config",
                        "--input",
                        str(audit_input),
                    ],
                )
            self.assertEqual(audit_code, 4)
            self.assertFalse(audit["productionReady"])
            self.assertEqual(audit["coverage"]["configDigest"], config["configDigest"])


if __name__ == "__main__":
    unittest.main()
