import copy
import tempfile
import unittest
from pathlib import Path

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class SnapshotIntegrityTest(unittest.TestCase):
    def test_snapshot_pins_profile_digest_and_load_rejects_cross_profile(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.snapshot import SnapshotValidationError, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            snapshot = ingest_test_snapshot(home, profile, sample_catalog(), now=NOW)
            self.assertEqual(snapshot["profileDigest"], sha256_digest(profile))
            with self.assertRaises(SnapshotValidationError):
                load_snapshot(home, "other-company", snapshot["snapshotId"])

    def test_higher_incomplete_snapshot_becomes_current_and_blocks_new_work(self) -> None:
        from guardian_core.canonical import read_canonical_json
        from guardian_core.paths import GuardianPaths

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            complete = ingest_test_snapshot(
                home, profile, sample_catalog(), now=NOW, sequence=1
            )
            incomplete_catalog = sample_catalog()
            incomplete_catalog["createdAt"] = "2026-07-15T11:30:00Z"
            incomplete_catalog["sourceEvidence"]["figmaVariables"]["modesPresent"] = False
            incomplete = ingest_test_snapshot(
                home, profile, incomplete_catalog, now=NOW, sequence=2
            )
            pointer = read_canonical_json(
                GuardianPaths(home).profile("example-company") / "current-snapshot.json"
            )
            self.assertEqual(incomplete["sourceState"], "source_incomplete")
            self.assertNotEqual(incomplete["snapshotId"], complete["snapshotId"])
            self.assertEqual(pointer["snapshotId"], incomplete["snapshotId"])
            self.assertEqual(pointer["approvalSequence"], 2)

    def test_duplicate_registry_identity_and_claimed_digest_conflict_fail(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError

        duplicate = sample_catalog()
        duplicate["registry"]["icons"].append(copy.deepcopy(duplicate["registry"]["icons"][0]))
        bad_digest = sample_catalog()
        bad_digest["sourceCut"]["catalogDigest"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            for catalog in (duplicate, bad_digest):
                with self.subTest(), self.assertRaises(SnapshotValidationError):
                    ingest_test_snapshot(home, profile, catalog, now=NOW)


    def test_approved_code_mappings_require_exact_parse_and_repository_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = sample_profile()

            missing_provenance = sample_catalog()
            missing_provenance["sourceCut"]["codeConnectParseDigest"] = None
            missing_provenance["sourceCut"]["repositoryCommit"] = None
            incomplete = ingest_test_snapshot(
                root / "mapped",
                profile,
                missing_provenance,
                now=NOW,
            )
            self.assertEqual(incomplete["sourceState"], "source_incomplete")
            self.assertFalse(incomplete["sourceComplete"])

            no_mappings = sample_catalog()
            no_mappings["sourceCut"]["codeConnectParseDigest"] = None
            no_mappings["sourceCut"]["repositoryCommit"] = None
            for plural in ("components", "icons"):
                for asset in no_mappings["registry"][plural]:
                    asset["codeMappings"] = []
            complete = ingest_test_snapshot(
                root / "unmapped",
                profile,
                no_mappings,
                now=NOW,
            )
            self.assertEqual(complete["sourceState"], "fresh")
            self.assertTrue(complete["sourceComplete"])
