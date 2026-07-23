import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import catalog_authority_public_key_path


class FoundationCliTest(unittest.TestCase):
    def invoke(self, home: Path, args: list[str]) -> tuple[int, str, str]:
        from guardian_core.cli import main

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch("guardian_core.cli.default_guardian_home", return_value=home),
            patch("guardian_core.resolver.default_guardian_home", return_value=home),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_doctor_install_and_verify(self) -> None:
        from guardian_core.canonical import canonical_json_text

        with tempfile.TemporaryDirectory() as directory:
            public_key = catalog_authority_public_key_path(Path(directory))
            code, out, err = self.invoke(Path(directory), [
                "doctor", "--install-policy",
                "--catalog-authority-public-key", str(public_key),
            ])
            self.assertEqual(code, 0, err)
            installed = json.loads(out)
            self.assertEqual(out, canonical_json_text(installed))
            self.assertEqual(installed["status"], "allowed")
            self.assertTrue(installed["policyInstalled"])

            code, out, err = self.invoke(Path(directory), ["doctor"])
            self.assertEqual(code, 0, err)
            verified = json.loads(out)
            self.assertEqual(out, canonical_json_text(verified))
            self.assertEqual(verified["policyDigest"], installed["policyDigest"])
            self.assertFalse(verified["policyInstalled"])

    def test_doctor_without_anchor_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, out, err = self.invoke(Path(directory), ["doctor"])
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            payload = json.loads(err)
            self.assertEqual(payload["status"], "invalid")

    def test_required_lifecycle_command_surface_parses_exact_inputs(self) -> None:
        from guardian_core.cli import build_parser

        cases = (
            (
                ["audit", "--profile", "example-company", "--run-id", "run-1", "--input", "audit.json"],
                "_audit_command",
            ),
            (
                ["finalize", "--profile", "example-company", "--run-id", "run-1", "--audit-result", "result.json"],
                "_finalize_command",
            ),
            (
                ["migrate", "--profile", "example-company", "--artifact", "state.json"],
                "_migrate_command",
            ),
        )
        parser = build_parser()
        for command, expected_handler in cases:
            with self.subTest(command=command):
                parsed = parser.parse_args(command)
                self.assertEqual(parsed.handler.__name__, expected_handler)

    def test_python_launcher_is_present(self) -> None:
        plugin_root = Path(__file__).resolve().parents[1]
        self.assertTrue((plugin_root / "scripts" / "guardian.py").is_file())
        self.assertTrue((plugin_root / "scripts" / "guardian.cmd").is_file())
        self.assertTrue((plugin_root / "scripts" / "guardian").is_file())
