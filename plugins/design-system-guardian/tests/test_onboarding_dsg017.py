from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.catalog_authority_test_support import new_test_catalog_authority
from tests.guardian_test_support import (
    catalog_authority_public_key_path,
    signed_test_catalog,
)
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


def file_state(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def onboarding_bundle(root: Path, *, profile: dict | None = None, catalog: dict | None = None) -> dict:
    from guardian_core.onboarding import prepare_onboarding_permission

    selected_profile = copy.deepcopy(profile or sample_profile())
    selected_catalog = copy.deepcopy(catalog or sample_catalog())
    authority_root = root / "authority"
    public_key = catalog_authority_public_key_path(authority_root)
    signed_catalog = signed_test_catalog(selected_catalog, selected_profile, now=NOW)
    preview = prepare_onboarding_permission(
        catalog_authority_public_key=public_key,
        profile_document=selected_profile,
        catalog_document=signed_catalog,
    )
    return {
        "schemaVersion": 1,
        "catalogAuthorityPublicKey": str(public_key.resolve()),
        "profile": selected_profile,
        "catalog": signed_catalog,
        "permission": {**preview["permissionBinding"], "granted": True},
    }


class GuardianOnboardingTest(unittest.TestCase):
    def test_authority_swap_after_permission_is_rejected_without_writes(self) -> None:
        from guardian_core.onboarding import OnboardingError, apply_onboarding

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            bundle = onboarding_bundle(root)
            Path(bundle["catalogAuthorityPublicKey"]).write_bytes(
                new_test_catalog_authority().public_pem
            )

            with self.assertRaises(OnboardingError):
                apply_onboarding(home, bundle)
            self.assertFalse(home.exists())
    def test_preview_validation_and_status_are_read_only_and_apply_requires_permission(self) -> None:
        from guardian_core.onboarding import (
            OnboardingError,
            inspect_onboarding,
            prepare_onboarding_permission,
            validate_onboarding_bundle,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            bundle = onboarding_bundle(root)

            preview = prepare_onboarding_permission(
                catalog_authority_public_key=Path(bundle["catalogAuthorityPublicKey"]),
                profile_document=bundle["profile"],
                catalog_document=bundle["catalog"],
            )
            self.assertEqual(preview["status"], "permission_required")
            self.assertEqual(preview["stage"], "permission")
            self.assertEqual(
                [item["fileKey"] for item in preview["figmaAuthority"]["libraryFiles"]],
                ["figma-brand", "figma-product"],
            )
            self.assertFalse(home.exists())

            validated = validate_onboarding_bundle(bundle)
            self.assertEqual(validated["profile"]["profileId"], "example-company")
            self.assertFalse(home.exists())

            status = inspect_onboarding(home, profile_id="example-company")
            self.assertEqual(status["status"], "setup_required")
            self.assertEqual(status["stage"], "policy")
            self.assertEqual(status["reasonCode"], "policy_anchor_missing")
            self.assertTrue(status["permissionRequired"])
            self.assertFalse(status["localChangesPerformed"])
            self.assertFalse(home.exists())

            denied = copy.deepcopy(bundle)
            denied["permission"]["granted"] = False
            with self.assertRaises(OnboardingError):
                validate_onboarding_bundle(denied)
            self.assertFalse(home.exists())

    def test_apply_is_fresh_install_atomic_and_idempotent(self) -> None:
        from guardian_core.onboarding import apply_onboarding, inspect_onboarding

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            bundle = onboarding_bundle(root)

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                first = apply_onboarding(home, bundle)
            self.assertEqual(first["status"], "allowed")
            self.assertEqual(first["stage"], "ready")
            self.assertTrue(first["localChangesPerformed"])
            self.assertTrue(first["freshHomePromoted"])
            self.assertTrue((home / "trust" / "policy-v1.json").is_file())
            self.assertTrue((home / "profiles" / "example-company" / "profile.json").is_file())
            before = file_state(home)

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                second = apply_onboarding(home, bundle)
            self.assertEqual(second["status"], "allowed")
            self.assertFalse(second["localChangesPerformed"])
            self.assertFalse(second["freshHomePromoted"])
            self.assertEqual(file_state(home), before)

            with patch("guardian_core.onboarding._utc_now", return_value=NOW):
                status = inspect_onboarding(home, profile_id="example-company")
            self.assertEqual(status["status"], "ready")
            self.assertEqual(status["snapshotId"], first["snapshotId"])

    def test_invalid_catalog_or_permission_never_creates_canonical_home(self) -> None:
        from guardian_core.onboarding import OnboardingError, apply_onboarding

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            wrong_permission = onboarding_bundle(root / "wrong-permission")
            wrong_permission["permission"]["profileDigest"] = "0" * 64
            wrong_home = root / "wrong-home"
            with self.assertRaises(OnboardingError):
                apply_onboarding(wrong_home, wrong_permission)
            self.assertFalse(wrong_home.exists())

            tampered = onboarding_bundle(root / "tampered")
            tampered["catalog"]["tokens"]["space"]["200"]["$value"]["value"] = 999
            from guardian_core.onboarding import prepare_onboarding_permission

            rebound = prepare_onboarding_permission(
                catalog_authority_public_key=Path(tampered["catalogAuthorityPublicKey"]),
                profile_document=tampered["profile"],
                catalog_document=tampered["catalog"],
            )
            tampered["permission"] = {**rebound["permissionBinding"], "granted": True}
            tampered_home = root / "tampered-home"
            tampered_home.mkdir()
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with self.assertRaises(OnboardingError):
                    apply_onboarding(tampered_home, tampered)
            self.assertTrue(tampered_home.is_dir())
            self.assertEqual(list(tampered_home.iterdir()), [])
            self.assertEqual(list(root.glob(".tampered-home.onboarding.*")), [])

    def test_existing_profile_revision_is_not_silently_replaced(self) -> None:
        from guardian_core.onboarding import OnboardingError, apply_onboarding

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            initial = onboarding_bundle(root / "initial")
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                apply_onboarding(home, initial)
            before = file_state(home)

            changed_profile = sample_profile()
            changed_profile["displayName"] = "Changed Company Name"
            changed = onboarding_bundle(root / "changed", profile=changed_profile)
            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                with self.assertRaises(OnboardingError):
                    apply_onboarding(home, changed)
            self.assertEqual(file_state(home), before)

    def test_incomplete_source_is_preserved_but_never_reported_ready(self) -> None:
        from guardian_core.onboarding import apply_onboarding, inspect_onboarding

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "guardian-home"
            catalog = sample_catalog()
            catalog["sourceEvidence"]["figmaVariables"]["valuesPresent"] = False
            bundle = onboarding_bundle(root, catalog=catalog)

            with patch("guardian_core.snapshot._utc_now", return_value=NOW):
                result = apply_onboarding(home, bundle)
            self.assertEqual(result["status"], "source_incomplete")
            self.assertEqual(result["stage"], "snapshot")
            self.assertFalse(result["ready"])

            with patch("guardian_core.onboarding._utc_now", return_value=NOW):
                status = inspect_onboarding(home, profile_id="example-company")
            self.assertEqual(status["status"], "source_incomplete")
            self.assertEqual(status["reasonCode"], "snapshot_source_incomplete")


if __name__ == "__main__":
    unittest.main()
