import base64
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import (
    DEFAULT_TEST_CATALOG_AUTHORITY,
    attest_catalog,
    new_test_catalog_authority,
)
from tests.guardian_test_support import catalog_authority_public_key_path
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class CatalogAuthorityAdversarialTest(unittest.TestCase):
    def provision(self, home: Path) -> dict:
        from guardian_core.policy import install_policy_anchor
        from guardian_core.profile import install_profile

        profile = sample_profile()
        install_policy_anchor(
            home,
            catalog_authority_public_key=catalog_authority_public_key_path(home),
        )
        install_profile(home, profile)
        return profile

    def test_every_signed_domain_and_attestation_mutation_is_rejected(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            approved = attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW)
            mutations: list[dict] = []

            token = copy.deepcopy(approved)
            token["tokens"]["space"]["200"]["$value"]["value"] = 9
            mutations.append(token)
            registry = copy.deepcopy(approved)
            registry["registry"]["icons"][0]["figma"]["assetKey"] = "substitute-icon"
            mutations.append(registry)
            source = copy.deepcopy(approved)
            source["sourceCut"]["repositoryCommit"] = "forged-commit"
            mutations.append(source)
            profile_id = copy.deepcopy(approved)
            profile_id["profileId"] = "other-company"
            mutations.append(profile_id)
            sequence = copy.deepcopy(approved)
            sequence["approvalAttestation"]["sequence"] = 2
            mutations.append(sequence)
            issued_at = copy.deepcopy(approved)
            issued_at["approvalAttestation"]["issuedAt"] = "2026-07-15T11:59:59Z"
            mutations.append(issued_at)
            algorithm = copy.deepcopy(approved)
            algorithm["approvalAttestation"]["algorithm"] = "rsa"
            mutations.append(algorithm)
            key_id = copy.deepcopy(approved)
            key_id["approvalAttestation"]["keyId"] = "0" * 64
            mutations.append(key_id)
            signature = copy.deepcopy(approved)
            signature["approvalAttestation"]["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
            mutations.append(signature)

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                for catalog in mutations:
                    with self.subTest(catalog=catalog), self.assertRaises(SnapshotValidationError):
                        ingest_snapshot(home, profile, catalog)

            backdated = attest_catalog(
                sample_catalog(),
                profile,
                sequence=1,
                issued_at=NOW.replace(hour=10),
            )
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with self.assertRaisesRegex(SnapshotValidationError, "predate"):
                    ingest_snapshot(home, profile, backdated)

    def test_complete_anchor_cannot_self_enroll_a_new_catalog_authority(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import install_policy_anchor

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self.provision(home)
            wrong = new_test_catalog_authority()
            wrong_path = home / "wrong-authority.pem"
            wrong_path.write_bytes(wrong.public_pem)
            with self.assertRaisesRegex(PolicyIntegrityError, "differs"):
                install_policy_anchor(home, catalog_authority_public_key=wrong_path)

    def test_same_sequence_same_content_is_idempotent_and_lower_replay_changes_nothing(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            sequence_two = attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = ingest_snapshot(home, profile, sequence_two)
                repeated = ingest_snapshot(home, profile, copy.deepcopy(sequence_two))
                lower = attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW)
                with self.assertRaisesRegex(SnapshotValidationError, "lower"):
                    ingest_snapshot(home, profile, lower)
            current = load_snapshot(home, "example-company")
            self.assertEqual(repeated, first)
            self.assertEqual(current["snapshotId"], first["snapshotId"])
            self.assertEqual(current["approvalSequence"], 2)

    def test_existing_run_stays_pinned_while_next_run_observes_new_sequence(self) -> None:
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.preflight import load_run_pin, preflight_snapshot
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            first_catalog = attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = ingest_snapshot(home, profile, first_catalog)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-before-publish",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )

            next_catalog = sample_catalog()
            next_catalog["createdAt"] = "2026-07-15T11:30:00Z"
            next_catalog["tokens"]["space"]["200"]["$value"]["value"] = 10
            next_catalog = attest_catalog(next_catalog, profile, sequence=2, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                second = ingest_snapshot(home, profile, next_catalog)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-after-publish",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )

            old_pin = load_run_pin(home, profile_id="example-company", run_id="run-before-publish")
            new_pin = load_run_pin(home, profile_id="example-company", run_id="run-after-publish")
            self.assertEqual(old_pin["snapshot"]["snapshotId"], first["snapshotId"])
            self.assertEqual(old_pin["pin"]["approvalSequence"], 1)
            self.assertEqual(new_pin["snapshot"]["snapshotId"], second["snapshotId"])
            self.assertEqual(new_pin["pin"]["approvalSequence"], 2)

    def test_higher_incomplete_observation_blocks_new_run_but_not_existing_pin(self) -> None:
        from guardian_core.policy import EXPECTED_POLICY_SHA256
        from guardian_core.preflight import load_run_pin, preflight_snapshot
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            first_catalog = attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = ingest_snapshot(home, profile, first_catalog)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-stable",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )

            incomplete = sample_catalog()
            incomplete["createdAt"] = "2026-07-15T11:30:00Z"
            incomplete["sourceEvidence"]["figmaVariables"]["modesPresent"] = False
            incomplete = attest_catalog(incomplete, profile, sequence=2, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                newest = ingest_snapshot(home, profile, incomplete)
            with patch("guardian_core.preflight._utc_now", return_value=NOW):
                blocked = preflight_snapshot(
                    home,
                    profile_id="example-company",
                    run_id="run-blocked",
                    policy_digest=EXPECTED_POLICY_SHA256,
                    project_root=home,
                )

            stable = load_run_pin(home, profile_id="example-company", run_id="run-stable")
            self.assertEqual(stable["snapshot"]["snapshotId"], first["snapshotId"])
            self.assertEqual(newest["approvalSequence"], 2)
            self.assertEqual(blocked["snapshotId"], newest["snapshotId"])
            self.assertEqual(blocked["status"], "source_incomplete")
            self.assertIsNone(blocked["pin"])


    def test_retained_newer_snapshot_blocks_deleted_record_and_replayed_pointer(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            paths = GuardianPaths(home)
            pointer_path = paths.profile("example-company") / "current-snapshot.json"

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW),
                )
                sequence_one_pointer = pointer_path.read_bytes()
                newest = ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW),
                )

            (paths.profile("example-company") / "approval-sequences" / "2.json").unlink()
            pointer_path.write_bytes(sequence_one_pointer)

            self.assertTrue(
                (paths.snapshots("example-company") / f"{newest['snapshotId']}.json").is_file(),
                "the newer immutable snapshot must remain for this rollback reproduction",
            )
            with self.assertRaisesRegex(
                SnapshotValidationError,
                "truncated|mismatch|replay|high-water",
            ):
                load_snapshot(home, "example-company")

    def test_snapshot_and_sequence_histories_must_match_in_both_directions(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        for removed_side in ("sequence", "snapshot"):
            with self.subTest(removed_side=removed_side), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                profile = self.provision(home)
                paths = GuardianPaths(home)
                with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                    first = ingest_snapshot(
                        home,
                        profile,
                        attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW),
                    )
                    ingest_snapshot(
                        home,
                        profile,
                        attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW),
                    )

                if removed_side == "sequence":
                    (paths.profile("example-company") / "approval-sequences" / "1.json").unlink()
                else:
                    (paths.snapshots("example-company") / f"{first['snapshotId']}.json").unlink()

                with self.assertRaisesRegex(
                    SnapshotValidationError,
                    "truncated|mismatch|history",
                ):
                    load_snapshot(home, "example-company")

    def test_complete_history_rejects_replayed_lower_current_pointer(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            pointer_path = GuardianPaths(home).profile("example-company") / "current-snapshot.json"
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW),
                )
                sequence_one_pointer = pointer_path.read_bytes()
                ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW),
                )
            pointer_path.write_bytes(sequence_one_pointer)

            with self.assertRaisesRegex(SnapshotValidationError, "replay|high-water"):
                load_snapshot(home, "example-company")

    def test_existing_history_rejects_a_noncontiguous_next_approval_sequence(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = self.provision(home)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = ingest_snapshot(
                    home,
                    profile,
                    attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW),
                )
                with self.assertRaisesRegex(SnapshotValidationError, "gap|contiguous"):
                    ingest_snapshot(
                        home,
                        profile,
                        attest_catalog(sample_catalog(), profile, sequence=3, issued_at=NOW),
                    )

            current = load_snapshot(home, "example-company")
            self.assertEqual(current["snapshotId"], first["snapshotId"])
            self.assertEqual(current["approvalSequence"], 1)

if __name__ == "__main__":
    unittest.main()
