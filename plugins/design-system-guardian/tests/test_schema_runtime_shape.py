


import copy
import json
import tempfile
import unittest
from pathlib import Path


class RuntimeSchemaShapeTest(unittest.TestCase):
    def test_snapshot_schema_describes_runtime_profile_and_registry_evidence(self) -> None:
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas" / "snapshot.schema.json").read_text(encoding="utf-8"))
        required = set(schema["required"])
        for field in (
            "profileDigest",
            "policyDigest",
            "authoritySeal",
            "assessedAt",
            "catalogEvidence",
            "refreshAttemptedAt",
            "lastSuccessfulRefreshAt",
            "sourceEvidence",
            "freshnessEvidence",
            "tokenProvenance",
            "resolver",
            "registry",
        ):
            self.assertIn(field, required)
            self.assertIn(field, schema["properties"])

    def test_schema_accepts_sealed_runtime_and_rejects_nested_shape_drift(self) -> None:
        from jsonschema import Draft202012Validator, ValidationError

        from tests.guardian_test_support import ingest_test_snapshot
        from tests.test_profile_snapshot import NOW, sample_catalog, sample_profile

        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas" / "snapshot.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        with tempfile.TemporaryDirectory() as directory:
            snapshot = ingest_test_snapshot(
                Path(directory), sample_profile(), sample_catalog(), now=NOW
            )
        validator.validate(snapshot)

        extra_token_field = copy.deepcopy(snapshot)
        extra_token_field["tokens"]["color.action.primary"]["rawFallback"] = "#FFFFFF"
        extra_asset_field = copy.deepcopy(snapshot)
        extra_asset_field["registry"]["icons"][0]["substitution"] = "Material.icon"
        for forged in (extra_token_field, extra_asset_field):
            with self.subTest(forged=forged), self.assertRaises(ValidationError):
                validator.validate(forged)
