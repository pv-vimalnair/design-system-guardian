import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class UnsupportedAdapterCliTest(unittest.TestCase):
    def test_disabled_flutter_profile_returns_exact_exit_four(self) -> None:
        from guardian_core.cli import main
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            profile["adapters"]["flutter"] = {"enabled": False}
            snapshot = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-disabled-flutter",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )
            output = home / "must-not-exist.json"
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
                        "run-disabled-flutter",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(code, 4)
            self.assertEqual(stdout.getvalue(), "")
            evidence = json.loads(stderr.getvalue())
            self.assertEqual(evidence["status"], "unsupported")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
