"""Regression coverage for approved components used from duplicated working files."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile


WORKING_FILE_KEY = "figma-working-copy"
WORKING_FILE_VERSION = "copy-17"


def working_profile() -> dict:
    profile = sample_profile()
    profile["figma"]["allowlistedWorkingFiles"] = [
        {"fileKey": WORKING_FILE_KEY, "name": "Approved working copy"}
    ]
    return profile


def working_catalog() -> dict:
    catalog = sample_catalog()
    catalog["sourceCut"]["figmaFiles"].append(
        {"fileKey": WORKING_FILE_KEY, "version": WORKING_FILE_VERSION}
    )
    catalog["registry"]["components"][0]["workingFileInstances"] = [
        {
            "fileKey": WORKING_FILE_KEY,
            "nodeId": "220:41",
            "sourceVersion": WORKING_FILE_VERSION,
            "nodeType": "INSTANCE",
            "canonicalAssetKey": "component-key-primary",
            "remote": True,
            "variant": "loading",
            "properties": {"size": "large"},
            "unapprovedOverrideFields": [],
        }
    ]
    return catalog


class WorkingFileInstanceTest(unittest.TestCase):
    def test_working_file_authority_is_explicit_disjoint_and_profile_scoped(self) -> None:
        from guardian_core.profile import ProfileValidationError, validate_profile
        from guardian_core.snapshot import SnapshotValidationError

        validate_profile(working_profile())
        overlap = working_profile()
        overlap["figma"]["allowlistedWorkingFiles"][0]["fileKey"] = "figma-brand"
        with self.assertRaises(ProfileValidationError):
            validate_profile(overlap)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SnapshotValidationError):
                ingest_test_snapshot(
                    Path(directory), sample_profile(), working_catalog(), now=NOW
                )

    def test_signed_working_file_instance_ingests_and_resolves_canonical_identity(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        with tempfile.TemporaryDirectory() as directory:
            snapshot = ingest_test_snapshot(
                Path(directory), working_profile(), working_catalog(), now=NOW
            )

        request = {
            "kind": "component",
            "identity": "button.primary",
            "variant": "loading",
            "properties": {"size": "large"},
            "figmaInstance": {
                "fileKey": WORKING_FILE_KEY,
                "nodeId": "220:41",
                "sourceVersion": WORKING_FILE_VERSION,
            },
        }
        with patch("guardian_core.resolver._utc_now", return_value=NOW):
            result = _resolve_verified_snapshot_identity(
                profile_id="example-company",
                snapshot=snapshot,
                request=request,
                policy_digest=snapshot["policyDigest"],
            )

        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["selectedIdentity"], "button.primary")
        self.assertEqual(result["evidence"]["match"], "exact_identity")
        self.assertEqual(
            result["evidence"]["workingFileInstance"]["fileKey"],
            WORKING_FILE_KEY,
        )

        without_locator = copy.deepcopy(request)
        without_locator.pop("figmaInstance")
        with patch("guardian_core.resolver._utc_now", return_value=NOW):
            omitted = _resolve_verified_snapshot_identity(
                profile_id="example-company",
                snapshot=snapshot,
                request=without_locator,
                policy_digest=snapshot["policyDigest"],
            )
        self.assertEqual(omitted["status"], "invalid")
        self.assertEqual(omitted["evidence"]["reason"], "working_instance_locator_required")
        self.assertIsNone(omitted["sentinel"])

        with patch("guardian_core.resolver._utc_now", return_value=NOW):
            unrelated = _resolve_verified_snapshot_identity(
                profile_id="example-company",
                snapshot=snapshot,
                request={"kind": "icon", "identity": "icon.check", "variant": "default"},
                policy_digest=snapshot["policyDigest"],
            )
        self.assertEqual(unrelated["status"], "invalid")
        self.assertEqual(unrelated["evidence"]["reason"], "working_instance_locator_required")

    def test_unknown_or_modified_working_instance_is_invalid_without_sentinel(self) -> None:
        from guardian_core.resolver import _resolve_verified_snapshot_identity

        with tempfile.TemporaryDirectory() as directory:
            snapshot = ingest_test_snapshot(
                Path(directory), working_profile(), working_catalog(), now=NOW
            )

        base_request = {
            "kind": "component",
            "identity": "button.primary",
            "variant": "loading",
            "properties": {"size": "large"},
            "figmaInstance": {
                "fileKey": WORKING_FILE_KEY,
                "nodeId": "220:41",
                "sourceVersion": WORKING_FILE_VERSION,
            },
        }
        for field, value in (
            ("fileKey", "another-copy"),
            ("nodeId", "220:99"),
            ("sourceVersion", "copy-18"),
        ):
            request = copy.deepcopy(base_request)
            request["figmaInstance"][field] = value
            with self.subTest(field=field):
                with patch("guardian_core.resolver._utc_now", return_value=NOW):
                    result = _resolve_verified_snapshot_identity(
                        profile_id="example-company",
                        snapshot=snapshot,
                        request=request,
                        policy_digest=snapshot["policyDigest"],
                    )
                self.assertEqual(result["status"], "invalid")
                self.assertIsNone(result["sentinel"])

    def test_unproven_copy_evidence_cannot_enter_a_snapshot(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError

        mutations = []
        local = working_catalog()
        local["registry"]["components"][0]["workingFileInstances"][0]["remote"] = False
        mutations.append(local)
        detached = working_catalog()
        detached["registry"]["components"][0]["workingFileInstances"][0]["nodeType"] = "COMPONENT"
        mutations.append(detached)
        overridden = working_catalog()
        overridden["registry"]["components"][0]["workingFileInstances"][0][
            "unapprovedOverrideFields"
        ] = ["fills"]
        mutations.append(overridden)

        for catalog in mutations:
            with self.subTest(binding=catalog["registry"]["components"][0]["workingFileInstances"][0]):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(SnapshotValidationError):
                        ingest_test_snapshot(
                            Path(directory), working_profile(), catalog, now=NOW
                        )


if __name__ == "__main__":
    unittest.main()
