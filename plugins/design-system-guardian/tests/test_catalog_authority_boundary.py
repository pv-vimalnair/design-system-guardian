import copy
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
    new_test_catalog_authority,
)
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class CatalogAuthorityBoundaryTest(unittest.TestCase):
    def provision(self, home: Path) -> tuple[dict, Path]:
        from guardian_core.policy import install_policy_anchor
        from guardian_core.profile import install_profile

        home.mkdir(parents=True, exist_ok=True)
        public_key = home / "catalog-authority-input.pem"
        public_key.write_bytes(DEFAULT_TEST_CATALOG_AUTHORITY.public_pem)
        install_policy_anchor(home, catalog_authority_public_key=public_key)
        profile = sample_profile()
        install_profile(home, profile)
        return profile, public_key

    def signed(self, catalog: dict, profile: dict, *, sequence: int) -> dict:
        return attest_catalog(catalog, profile, sequence=sequence, issued_at=NOW)

    def test_unsigned_and_wrong_key_catalogs_are_rejected(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            unsigned = sample_catalog()
            unsigned["tokens"]["outside"] = {
                "$type": "color",
                "nearest-blue": {
                    "$value": {
                        "colorSpace": "srgb",
                        "components": [0.0, 0.3, 1.0],
                        "alpha": 1,
                    }
                },
            }
            wrong = attest_catalog(
                sample_catalog(),
                profile,
                sequence=1,
                issued_at=NOW,
                authority=new_test_catalog_authority(),
            )
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                for catalog in (unsigned, wrong):
                    with self.subTest(catalog=catalog), self.assertRaises(SnapshotValidationError):
                        ingest_snapshot(home, profile, catalog)

    def test_valid_signed_catalog_reaches_allowed_resolution_end_to_end(self) -> None:
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.preflight import load_run_pin, preflight_snapshot
        from guardian_core.resolver import _resolve_verified_snapshot_identity
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                snapshot = ingest_snapshot(home, profile, self.signed(sample_catalog(), profile, sequence=1))
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="signed-e2e",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )
            pinned = load_run_pin(home, profile_id="example-company", run_id="signed-e2e")
            with patch("guardian_core.resolver._utc_now", return_value=NOW):
                result = _resolve_verified_snapshot_identity(
                    profile_id="example-company",
                    snapshot=pinned["snapshot"],
                    request={
                        "kind": "icon",
                        "identity": "icon.check",
                        "variant": "default",
                        "properties": {},
                    },
                    policy_digest=EXPECTED_POLICY_SHA256,
                )
            self.assertEqual(snapshot["approvalSequence"], 1)
            self.assertEqual(preflight["status"], "allowed")
            self.assertEqual(preflight["pin"]["approvalSequence"], 1)
            self.assertEqual(result["status"], "allowed")
            self.assertEqual(result["selectedIdentity"], "icon.check")

    def test_production_tree_contains_no_private_signing_capability(self) -> None:
        core = Path(__file__).resolve().parents[1] / "guardian_core"
        production = "\n".join(path.read_text(encoding="utf-8") for path in core.glob("*.py"))
        self.assertNotIn("Ed25519PrivateKey", production)
        self.assertNotIn(".sign(", production)
        self.assertNotIn("def sign", production)

    def test_cli_rejects_backdated_now_and_arbitrary_preflight_snapshot(self) -> None:
        from guardian_core.cli import build_parser

        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["snapshot", "ingest", "--profile", "p", "--input", "c", "--now", "2020-01-01T00:00:00Z"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["preflight", "--profile", "p", "--run-id", "r", "--snapshot", "0" * 64])
        with self.assertRaises(SystemExit):
            parser.parse_args(["resolve", "--profile", "p", "--run-id", "r", "--request", "q", "--now", "2020-01-01T00:00:00Z"])

    def test_preflight_pins_only_the_sealed_current_snapshot(self) -> None:
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.preflight import preflight_snapshot
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            first_catalog = self.signed(sample_catalog(), profile, sequence=1)
            second_catalog = sample_catalog()
            second_catalog["createdAt"] = "2026-07-15T11:30:00Z"
            second_catalog["registry"]["icons"] = []
            second_catalog = self.signed(second_catalog, profile, sequence=2)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = ingest_snapshot(home, profile, first_catalog)
                second = ingest_snapshot(home, profile, second_catalog)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                result = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="current-only",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )
            self.assertNotEqual(first["snapshotId"], second["snapshotId"])
            self.assertEqual(result["snapshotId"], second["snapshotId"])
            self.assertEqual(result["pin"]["approvalSequence"], 2)

    def test_sequence_downgrade_and_equal_sequence_conflict_are_rejected(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            sequence_two = self.signed(sample_catalog(), profile, sequence=2)
            different_two = sample_catalog()
            different_two["createdAt"] = "2026-07-15T11:30:00Z"
            different_two["tokens"]["space"]["200"]["$value"]["value"] = 10
            different_two = self.signed(different_two, profile, sequence=2)
            sequence_one = self.signed(sample_catalog(), profile, sequence=1)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                ingest_snapshot(home, profile, sequence_two)
                for catalog in (sequence_one, different_two):
                    with self.subTest(catalog=catalog), self.assertRaises(SnapshotValidationError):
                        ingest_snapshot(home, profile, catalog)

    def test_concurrent_promotion_cannot_finish_on_the_lower_sequence(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile, _ = self.provision(home)
            catalogs = []
            for sequence in (1, 2):
                catalog = sample_catalog()
                catalog["createdAt"] = f"2026-07-15T11:{sequence}0:00Z"
                catalogs.append(self.signed(catalog, profile, sequence=sequence))
            barrier = threading.Barrier(2)

            def ingest(catalog: dict) -> None:
                barrier.wait()
                try:
                    ingest_snapshot(home, profile, catalog)
                except SnapshotValidationError:
                    pass

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(ingest, catalogs))
            current = load_snapshot(home, "example-company")
            self.assertEqual(current["approvalSequence"], 2)

    def test_runtime_dependency_is_pinned(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "requirements.txt").read_text(encoding="utf-8").strip(), "cryptography==46.0.7\ncffi==2.1.0\npycparser==3.0")


if __name__ == "__main__":
    unittest.main()
