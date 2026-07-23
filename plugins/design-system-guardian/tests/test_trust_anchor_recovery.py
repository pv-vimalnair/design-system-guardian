import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import attest_catalog, new_test_catalog_authority
from tests.guardian_test_support import ingest_test_snapshot, install_test_context
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class TrustAnchorRecoveryTest(unittest.TestCase):
    def test_catalog_public_key_swap_breaks_policy_and_catalog_ingestion(self) -> None:
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.paths import GuardianPaths
        from guardian_core.policy import verify_policy_anchor
        from guardian_core.snapshot import ingest_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            ingest_test_snapshot(home, profile, sample_catalog(), now=NOW, sequence=1)
            attacker = new_test_catalog_authority()
            GuardianPaths(home).catalog_authority_public_key.write_bytes(attacker.public_pem)

            with self.assertRaises(PolicyIntegrityError):
                verify_policy_anchor(home)

            invented = sample_catalog()
            invented["tokens"]["outside"] = {
                "$type": "color",
                "nearest-blue": {
                    "$value": {
                        "colorSpace": "srgb",
                        "components": [0.0, 0.3, 1.0],
                        "alpha": 1,
                    }
                },
            }
            signed = attest_catalog(
                invented,
                profile,
                sequence=2,
                issued_at=NOW,
                authority=attacker,
            )
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with self.assertRaises(PolicyIntegrityError):
                    ingest_snapshot(home, profile, signed)

    def test_deleted_current_pointer_cannot_reset_approval_high_water(self) -> None:
        from guardian_core.paths import GuardianPaths
        from guardian_core.snapshot import SnapshotValidationError, ingest_snapshot, load_snapshot

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = sample_profile()
            install_test_context(home, profile)
            sequence_two = attest_catalog(sample_catalog(), profile, sequence=2, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                newest = ingest_snapshot(home, profile, sequence_two)

            pointer = GuardianPaths(home).profile("example-company") / "current-snapshot.json"
            pointer.unlink()
            sequence_one = attest_catalog(sample_catalog(), profile, sequence=1, issued_at=NOW)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with self.assertRaisesRegex(SnapshotValidationError, "lower"):
                    ingest_snapshot(home, profile, sequence_one)

            recovered = load_snapshot(home, "example-company")
            self.assertEqual(recovered["snapshotId"], newest["snapshotId"])
            self.assertEqual(recovered["approvalSequence"], 2)


if __name__ == "__main__":
    unittest.main()
