from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


class PersonalTrustOriginTest(unittest.TestCase):
    def test_fresh_personal_capability_records_no_external_origin(self) -> None:
        from guardian_core.policy import (
            install_personal_policy_anchor,
            verify_personal_capability,
            verify_policy_anchor,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "guardian-home"

            install_personal_policy_anchor(home)
            capability = verify_personal_capability(home)

            self.assertEqual(capability["enrollmentOrigin"], "fresh_personal")
            self.assertIsNone(capability["externalCatalogAuthorityKeyId"])
            self.assertEqual(verify_policy_anchor(home), capability["policyDigest"])

    def test_hybrid_capability_fails_if_external_authority_disappears(self) -> None:
        from guardian_core.catalog_authority import verify_pinned_catalog_authority
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.paths import GuardianPaths
        from guardian_core.policy import (
            install_personal_policy_anchor,
            verify_personal_capability,
            verify_policy_anchor,
        )

        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "guardian-home"
            ingest_test_snapshot(
                home,
                sample_profile(),
                sample_catalog(),
                now=NOW,
            )
            _, external_key_id = verify_pinned_catalog_authority(home)

            install_personal_policy_anchor(home)
            capability = verify_personal_capability(home)

            self.assertEqual(capability["enrollmentOrigin"], "external_hybrid")
            self.assertEqual(
                capability["externalCatalogAuthorityKeyId"],
                external_key_id,
            )
            self.assertEqual(verify_policy_anchor(home), capability["policyDigest"])

            paths = GuardianPaths(home)
            paths.catalog_authority_public_key.unlink()
            paths.catalog_authority_binding.unlink()

            with self.assertRaisesRegex(PolicyIntegrityError, "lost.*external"):
                verify_policy_anchor(home)

    def test_exact_generated_shape_remains_valid_for_legacy_enterprise_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "guardian-home"
            profile_id = "personal-" + "a" * 40

            snapshot = ingest_test_snapshot(
                home,
                sample_profile(profile_id),
                sample_catalog(profile_id),
                now=NOW,
            )

            self.assertEqual(snapshot["profileId"], profile_id)
            self.assertEqual(
                snapshot["catalogEvidence"]["approvalAttestation"]["algorithm"],
                "ed25519",
            )


    def test_personal_authority_rejects_unrelated_selection_digest(self) -> None:
        from guardian_core.canonical import sha256_digest
        from guardian_core.errors import PolicyIntegrityError
        from guardian_core.policy import create_personal_profile_authority_binding
        from guardian_core.profile import load_profile
        from tests.test_personal_selection_dsg028 import apply_selection

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            project = root / "project"
            project.mkdir()
            applied = apply_selection(home, project, run_id="authority-scope")
            profile = load_profile(home, applied["profileId"])

            with self.assertRaisesRegex(PolicyIntegrityError, "do not match"):
                create_personal_profile_authority_binding(
                    home,
                    profile_id=applied["profileId"],
                    profile_digest=sha256_digest(profile),
                    selection_set_digest="f" * 64,
                )



if __name__ == "__main__":
    unittest.main()
