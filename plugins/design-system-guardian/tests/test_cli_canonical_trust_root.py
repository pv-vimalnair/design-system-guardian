import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import attest_catalog, new_test_catalog_authority
from tests.guardian_test_support import install_test_context
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class CanonicalCliTrustRootTest(unittest.TestCase):
    def test_parser_rejects_alternate_guardian_home(self) -> None:
        from guardian_core.cli import build_parser

        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                ["--guardian-home", r"C:\attacker-home", "doctor"]
            )

    def test_environment_variables_cannot_redirect_default_home(self) -> None:
        from guardian_core.paths import default_guardian_home

        expected = default_guardian_home()
        with tempfile.TemporaryDirectory() as directory:
            attacker_home = Path(directory) / "attacker"
            with (
                patch.dict(
                    os.environ,
                    {
                        "HOME": str(attacker_home),
                        "USERPROFILE": str(attacker_home),
                        "HOMEDRIVE": "Z:",
                        "HOMEPATH": r"\attacker",
                        "DESIGN_SYSTEM_GUARDIAN_HOME": str(attacker_home),
                    },
                    clear=False,
                ),
                patch("guardian_core.paths.Path.home", return_value=attacker_home),
            ):
                self.assertEqual(default_guardian_home(), expected)

    def test_valid_alternate_authority_cannot_be_selected_by_cli_or_environment(self) -> None:
        from guardian_core.cli import main
        from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor
        from guardian_core.preflight import preflight_snapshot
        from guardian_core.profile import install_profile
        from guardian_core.resolver import _resolve_verified_snapshot_identity
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alternate = root / "attacker-root"
            canonical = root / "canonical-user" / ".design-system-guardian"
            authority = new_test_catalog_authority()
            public_key = root / "attacker-public.pem"
            public_key.write_bytes(authority.public_pem)
            profile = sample_profile()
            install_policy_anchor(
                alternate,
                catalog_authority_public_key=public_key,
            )
            install_profile(alternate, profile)
            catalog = sample_catalog()
            catalog["tokens"]["outside"] = {
                "$type": "color",
                "nearest-blue": {
                    "$value": {
                        "colorSpace": "srgb",
                        "components": [0.0, 0.3, 1.0],
                        "alpha": 1,
                    }
                },
            }
            approved = attest_catalog(
                catalog,
                profile,
                sequence=1,
                issued_at=NOW,
                authority=authority,
            )
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                ingest_snapshot(alternate, profile, approved)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    alternate,
                    profile_id="example-company",
                    run_id="attacker-run",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=alternate,
                )
            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                internal_result = _resolve_verified_snapshot_identity(
                    profile_id="example-company",
                    snapshot=__import__(
                        "guardian_core.preflight", fromlist=["load_run_pin"]
                    ).load_run_pin(
                        alternate,
                        profile_id="example-company",
                        run_id="attacker-run",
                    )["snapshot"],
                    request={
                        "kind": "token",
                        "identity": "outside.nearest-blue",
                        "tokenType": "color",
                    },
                    policy_digest=EXPECTED_POLICY_SHA256,
                )
            self.assertEqual(internal_result["status"], "allowed")

            with self.assertRaises(SystemExit):
                main(["--guardian-home", str(alternate), "doctor"])

            out, err = io.StringIO(), io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"DESIGN_SYSTEM_GUARDIAN_HOME": str(alternate)},
                    clear=False,
                ),
                patch("guardian_core.cli.default_guardian_home", return_value=canonical),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                code = main(
                    [
                        "resolve",
                        "--profile",
                        "example-company",
                        "--run-id",
                        "attacker-run",
                        "--request",
                        str(root / "unused-request.json"),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertFalse((canonical / "trust").exists())


    def test_malformed_signed_registry_returns_canonical_exit_two(self) -> None:
        from guardian_core.cli import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            profile = sample_profile()
            install_test_context(home, profile)
            catalog = sample_catalog()
            catalog["registry"]["icons"][0]["variants"] = [{}]
            malformed = attest_catalog(catalog, profile, sequence=1, issued_at=NOW)
            catalog_file = root / "malformed-catalog.json"
            catalog_file.write_text(json.dumps(malformed), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with (
                patch("guardian_core.cli.default_guardian_home", return_value=home),
                patch("guardian_core.snapshot._utc_now", return_value=NOW),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                code = main(
                    [
                        "snapshot",
                        "ingest",
                        "--profile",
                        "example-company",
                        "--input",
                        str(catalog_file),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(json.loads(err.getvalue())["status"], "invalid")
            self.assertNotIn("Traceback", err.getvalue())

if __name__ == "__main__":
    unittest.main()
