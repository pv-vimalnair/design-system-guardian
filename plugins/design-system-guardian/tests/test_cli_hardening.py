import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import catalog_authority_public_key_path


class CliHardeningTest(unittest.TestCase):
    def invoke(self, home: Path, args: list[str]) -> tuple[int, str, str]:
        from guardian_core.cli import main

        out = io.StringIO()
        err = io.StringIO()
        with (
            patch("guardian_core.cli.default_guardian_home", return_value=home),
            patch("guardian_core.resolver.default_guardian_home", return_value=home),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_repeat_install_emits_actual_created_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            public_key = catalog_authority_public_key_path(home)
            install_args = [
                "doctor", "--install-policy",
                "--catalog-authority-public-key", str(public_key),
            ]
            first, first_out, _ = self.invoke(home, install_args)
            second, second_out, _ = self.invoke(home, install_args)
            self.assertEqual((first, second), (0, 0))
            self.assertTrue(json.loads(first_out)["policyInstalled"])
            self.assertFalse(json.loads(second_out)["policyInstalled"])

    def test_filesystem_failure_is_canonical_integrity_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home_file = Path(directory) / "not-a-directory"
            home_file.write_text("occupied", encoding="utf-8")
            code, out, err = self.invoke(home_file, ["doctor", "--install-policy"])
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertEqual(json.loads(err)["status"], "invalid")
