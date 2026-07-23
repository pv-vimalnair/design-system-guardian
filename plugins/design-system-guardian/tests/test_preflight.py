import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class PreflightPinTest(unittest.TestCase):
    def test_same_run_cannot_be_repinned_and_offline_grace_is_explicit(self) -> None:
        from guardian_core.preflight import PreflightError, preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            fresh = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW, sequence=1)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                first = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-fixed",
                    policy_digest=fresh["policyDigest"],
                    project_root=home,
                )
            self.assertEqual(first["status"], "allowed")
            self.assertFalse(first["degraded"])
            self.assertTrue(first["pinCreated"])
            self.assertNotIn("productionReady", first)

            changed_catalog = sample_catalog()
            changed_catalog["createdAt"] = "2026-07-15T11:30:00Z"
            changed_catalog["tokens"]["space"]["200"]["$value"]["value"] = 10
            changed = ingest_test_snapshot(home, profile, changed_catalog, now=NOW, sequence=2)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                with self.assertRaises(PreflightError):
                    preflight_snapshot(
                        home,
                        profile_id="example-company",
                        run_id="run-fixed",
                        policy_digest=changed["policyDigest"],
                        project_root=home,
                    )

    def test_seven_day_snapshot_is_stale_and_not_pinned(self) -> None:
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            snapshot = ingest_test_snapshot(
                home,
                sample_profile(),
                sample_catalog(),
                now=NOW,
            )
            stale_now = datetime(2026, 7, 22, 12, tzinfo=timezone.utc)
            with patch("guardian_core.preflight._utc_now", return_value=stale_now):
                result = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-stale",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )
            self.assertEqual(result["status"], "stale")
            self.assertIsNone(result["pin"])
            self.assertFalse(result["pinCreated"])
            self.assertNotIn("productionReady", result)
