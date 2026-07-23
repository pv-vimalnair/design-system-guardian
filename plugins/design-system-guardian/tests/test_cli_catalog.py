import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import (
    catalog_authority_public_key_path,
    ingest_test_snapshot,
    signed_test_catalog,
)
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class CatalogCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock_patchers = [
            patch("guardian_core.snapshot._utc_now", return_value=NOW),
            patch("guardian_core.preflight._utc_now", return_value=NOW),
            patch("guardian_core.resolver._utc_now", return_value=NOW),
        ]
        for clock in self.clock_patchers:
            clock.start()
            self.addCleanup(clock.stop)

    def invoke(self, home: Path, args: list[str]) -> tuple[int, str, str]:
        from guardian_core.cli import main

        out, err = io.StringIO(), io.StringIO()
        with (
            patch("guardian_core.cli.default_guardian_home", return_value=home),
            patch("guardian_core.resolver.default_guardian_home", return_value=home),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_profile_snapshot_preflight_and_resolve_command_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            profile = sample_profile()
            profile_file = root / "profile.json"
            catalog_file = root / "catalog.json"
            request_file = root / "request.json"
            public_key = catalog_authority_public_key_path(home)
            project = root / "product"
            project.mkdir()
            self.write_json(profile_file, profile)
            self.write_json(
                catalog_file,
                signed_test_catalog(sample_catalog(), profile, now=NOW),
            )
            self.write_json(
                request_file,
                {"kind": "token", "identity": "color.action.primary", "tokenType": "color"},
            )

            code, _, err = self.invoke(home,
                [
                    "doctor", "--install-policy",
                    "--catalog-authority-public-key", str(public_key),
                ]
            )
            self.assertEqual(code, 0, err)
            code, out, err = self.invoke(home,
                [
                    "profile", "validate",
                    "--input", str(profile_file), "--install",
                ]
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["profileId"], "example-company")

            code, out, err = self.invoke(home,
                [
                    "snapshot", "ingest",
                    "--profile", "example-company", "--input", str(catalog_file),
                ]
            )
            self.assertEqual(code, 0, err)
            ingested = json.loads(out)
            snapshot_id = ingested["snapshotId"]
            self.assertTrue(ingested["snapshotUsable"])
            self.assertNotIn("productionReady", ingested)

            code, out, err = self.invoke(home,
                [
                    "preflight",
                    "--profile", "example-company", "--run-id", "run-cli-001",
                    "--project-root", str(project),
                ]
            )
            self.assertEqual(code, 0, err)
            preflight = json.loads(out)
            self.assertEqual(preflight["status"], "allowed")
            self.assertEqual(preflight["pin"]["snapshotId"], snapshot_id)
            self.assertTrue(preflight["pinCreated"])
            self.assertNotIn("productionReady", preflight)

            code, out, err = self.invoke(home,
                [
                    "resolve", "--profile", "example-company",
                    "--run-id", "run-cli-001", "--request", str(request_file),
                ]
            )
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["selectedIdentity"], "color.action.primary")

    def test_missing_resolution_returns_exit_one_and_sentinel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            snapshot = ingest_test_snapshot(
                home,
                sample_profile(),
                sample_catalog(),
                now=NOW,
            )
            project = root / "product"
            project.mkdir()
            code, _, err = self.invoke(home,
                [
                    "preflight", "--profile", "example-company",
                    "--run-id", "run-cli-missing",
                    "--project-root", str(project),
                ]
            )
            self.assertEqual(code, 0, err)

            request = root / "missing.json"
            self.write_json(
                request,
                {"requestId": "req-cli-missing", "kind": "icon", "identity": "icon.receipt"},
            )
            code, out, err = self.invoke(home,
                [
                    "resolve", "--profile", "example-company",
                    "--run-id", "run-cli-missing", "--request", str(request),
                ]
            )
            self.assertEqual(code, 1, err)
            self.assertEqual(snapshot["approvalSequence"], 1)
            self.assertFalse(json.loads(out)["sentinel"]["productionReady"])
