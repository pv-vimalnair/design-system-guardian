"""Schema and ambiguity checks for duplicate working-file evidence."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

from tests.guardian_test_support import ingest_test_snapshot
from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile
from tests.test_working_file_instances_dsg016 import (
    WORKING_FILE_KEY,
    WORKING_FILE_VERSION,
    working_catalog,
    working_profile,
)


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class WorkingFileInstanceSchemaTest(unittest.TestCase):
    def test_new_snapshot_and_allowed_resolution_match_public_schemas(self) -> None:
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
            resolution = _resolve_verified_snapshot_identity(
                profile_id="example-company",
                snapshot=snapshot,
                request=request,
                policy_digest=snapshot["policyDigest"],
            )

        snapshot_schema = json.loads(
            (PLUGIN_ROOT / "schemas/snapshot.schema.json").read_text(encoding="utf-8")
        )
        resolution_schema = json.loads(
            (PLUGIN_ROOT / "schemas/resolution.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(snapshot_schema).validate(snapshot)
        Draft202012Validator(resolution_schema).validate(resolution)

        missing_proof = copy.deepcopy(resolution)
        missing_proof["evidence"].pop("workingFileInstance")
        with self.assertRaises(ValidationError):
            Draft202012Validator(resolution_schema).validate(missing_proof)

    def test_unbound_working_file_and_duplicate_locator_fail_ingestion(self) -> None:
        from guardian_core.snapshot import SnapshotValidationError

        unbound = sample_catalog()
        unbound["sourceCut"]["figmaFiles"].append(
            {"fileKey": WORKING_FILE_KEY, "version": WORKING_FILE_VERSION}
        )

        duplicate = working_catalog()
        duplicate_binding = copy.deepcopy(
            duplicate["registry"]["components"][0]["workingFileInstances"][0]
        )
        duplicate_binding.update(
            {
                "canonicalAssetKey": "icon-key-check",
                "variant": "default",
                "properties": {},
            }
        )
        duplicate["registry"]["icons"][0]["workingFileInstances"] = [duplicate_binding]

        for catalog in (unbound, duplicate):
            with self.subTest(catalog=catalog):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(SnapshotValidationError):
                        ingest_test_snapshot(
                            Path(directory), working_profile(), catalog, now=NOW
                        )


if __name__ == "__main__":
    unittest.main()
