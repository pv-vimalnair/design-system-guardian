import copy
import io
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import (
    catalog_authority_public_key_path,
    ingest_test_snapshot,
    install_test_context,
    signed_test_catalog,
)
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class IntegrityHardeningTest(unittest.TestCase):
    def provision(self, home: Path) -> tuple[dict, dict]:
        profile = sample_profile()
        snapshot = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW)
        return profile, snapshot

    def test_policy_install_transactionally_creates_non_emitted_authority_key(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.policy import install_policy_anchor, verify_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = install_policy_anchor(
                home,
                catalog_authority_public_key=catalog_authority_public_key_path(home),
            )
            paths = GuardianPaths(home)
            self.assertEqual(len(paths.snapshot_authority_key.read_bytes()), 32)
            self.assertEqual(verify_policy_anchor(home), result.digest)
            self.assertNotIn(paths.snapshot_authority_key.read_bytes().hex(), result.digest)

    def test_two_file_legacy_anchor_is_rejected_as_incompatible_not_upgraded(self) -> None:
        from guardian_core.canonical import atomic_write_bytes, atomic_write_json
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.paths import GuardianPaths
        from guardian_core.policy import EXPECTED_POLICY_SHA256, install_policy_anchor, shipped_policy

        with tempfile.TemporaryDirectory() as directory:
            paths = GuardianPaths(Path(directory))
            atomic_write_json(paths.policy, shipped_policy())
            atomic_write_bytes(paths.policy_seal, (EXPECTED_POLICY_SHA256 + "\n").encode("ascii"))
            with self.assertRaisesRegex(PolicyIntegrityError, "incompatible"):
                install_policy_anchor(paths.home)
            self.assertFalse(paths.snapshot_authority_key.exists())
            self.assertFalse(paths.catalog_authority_public_key.exists())

    def test_forged_self_hashed_snapshot_is_rejected_before_resolution(self) -> None:
        from guardian_core.canonical import atomic_write_json, sha256_digest
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _, snapshot = self.provision(home)
            forged = copy.deepcopy(snapshot)
            forged["tokens"]["color.action.primary"]["value"]["components"] = [1, 0, 0]
            forged["catalogDigest"] = sha256_digest(
                {
                    "tokenProvenance": forged["tokenProvenance"],
                    "tokens": forged["tokens"],
                    "resolver": forged["resolver"],
                    "registry": forged["registry"],
                }
            )
            forged["sourceCut"]["catalogDigest"] = forged["catalogDigest"]
            forged["snapshotId"] = ""
            forged["snapshotId"] = sha256_digest(
                {key: value for key, value in forged.items() if key not in {"snapshotId", "authoritySeal"}}
            )
            forged["authoritySeal"] = "0" * 64
            path = GuardianPaths(home).snapshots("example-company") / f"{forged['snapshotId']}.json"
            atomic_write_json(path, forged)
            with self.assertRaisesRegex(SnapshotValidationError, "authority seal"):
                load_snapshot(home, "example-company", forged["snapshotId"])

    def test_full_load_revalidates_original_catalog_evidence(self) -> None:
        from guardian_core.canonical import atomic_write_json
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _, snapshot = self.provision(home)
            damaged = copy.deepcopy(snapshot)
            damaged["catalogEvidence"]["registry"]["icons"][0]["figma"]["published"] = False
            path = GuardianPaths(home).snapshots("example-company") / f"{snapshot['snapshotId']}.json"
            atomic_write_json(path, damaged)
            with patch("guardian_core.snapshot.verify_authority_seal", return_value=None):
                with self.assertRaises(SnapshotValidationError):
                    load_snapshot(home, "example-company", snapshot["snapshotId"])

    def test_profile_snapshot_and_run_paths_reject_redirects(self) -> None:
        from guardian_core.paths import PathIntegrityError, assert_guardian_storage_path

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            outside = root / "outside"
            home.mkdir()
            outside.mkdir()
            redirect = home / "profiles"
            try:
                redirect.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Directory symlink creation is not permitted on this Windows host")
            with self.assertRaises(PathIntegrityError):
                assert_guardian_storage_path(home, redirect / "example-company" / "profile.json")

    def test_concurrent_same_run_pins_are_coherent_and_idempotent(self) -> None:
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _, snapshot = self.provision(home)
            barrier = threading.Barrier(2)

            def attempt() -> str:
                barrier.wait()
                return preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="race-fixed",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )["snapshotId"]

            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(lambda _: attempt(), range(2)))
            self.assertEqual(results, [snapshot["snapshotId"], snapshot["snapshotId"]])

    def test_cli_resolve_requires_run_pin_and_ignores_unpinned_snapshot_selection(self) -> None:
        from guardian_core.cli import main
        from guardian_core.preflight import preflight_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            _, snapshot = self.provision(home)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-resolve",
                    policy_digest=snapshot["policyDigest"],
                    project_root=home,
                )
            request_path = home / "request.json"
            request_path.write_text(
                json.dumps({"kind": "token", "identity": "color.action.primary"}),
                encoding="utf-8",
            )
            out, err = io.StringIO(), io.StringIO()
            with (
                patch("guardian_core.cli.default_guardian_home", return_value=home),
                patch("guardian_core.resolver.default_guardian_home", return_value=home),
                patch("guardian_core.resolver._utc_now", return_value=NOW),
                redirect_stdout(out),
                redirect_stderr(err),
            ):
                code = main(
                        [
                            "resolve",
                            "--profile", "example-company", "--run-id", "run-resolve",
                            "--request", str(request_path),
                        ]
                    )
            self.assertEqual(code, 0, err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["snapshotId"], snapshot["snapshotId"])

    def test_timestamp_order_and_future_refresh_evidence_are_rejected(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot

        mutations = []
        future_attempt = sample_catalog()
        future_attempt["refreshAttemptedAt"] = "2026-07-15T13:00:00Z"
        mutations.append(future_attempt)
        inverted = sample_catalog()
        inverted["lastSuccessfulRefreshAt"] = "2026-07-15T11:30:00Z"
        mutations.append(inverted)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            install_test_context(home, profile)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                for catalog in mutations:
                    approved = signed_test_catalog(catalog, profile, now=NOW)
                    with self.subTest(catalog=catalog), self.assertRaises(SnapshotValidationError):
                        ingest_snapshot(home, profile, approved)

    def test_sentinel_manifest_is_canonical_and_drift_blocks_generation(self) -> None:
        from guardian_core.canonical import atomic_write_json
        from guardian_core.sentinels import SentinelIntegrityError, load_sentinel_manifest

        manifest = load_sentinel_manifest()
        with tempfile.TemporaryDirectory() as directory:
            forged = copy.deepcopy(manifest)
            forged["style"]["background"] = "#0000FF"
            path = Path(directory) / "manifest.json"
            atomic_write_json(path, forged)
            with patch("guardian_core.sentinels.sentinel_manifest_path", return_value=path):
                with self.assertRaises(SentinelIntegrityError):
                    load_sentinel_manifest()


if __name__ == "__main__":
    unittest.main()
