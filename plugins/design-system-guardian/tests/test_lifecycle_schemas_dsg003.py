import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "schemas" / "lifecycle"

class LifecycleSchemaTest(unittest.TestCase):
    def test_exact_lifecycle_schema_set_is_strict_draft_2020_12(self) -> None:
        expected = {
            "analysis-attestation.schema.json",
            "sealed-run-artifact.schema.json",
            "reconciliation-state.schema.json",
            "migration-record.schema.json",
        }
        self.assertEqual({path.name for path in ROOT.glob("*.schema.json")}, expected)
        for name in expected:
            schema = json.loads((ROOT / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(schema.get("additionalProperties", True), name)
            self.assertIn("schemaVersion", schema["required"])
            self.assertEqual(schema["properties"]["schemaVersion"], {"const": 1})

    def test_sealed_artifact_schema_requires_digest_policy_and_authority_bindings(self) -> None:
        schema = json.loads((ROOT / "sealed-run-artifact.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(schema["properties"]["artifactType"]["enum"]), {"analysis-attestation", "audit-result", "coverage", "build-plan", "run-manifest", "post-run-assessment", "judgment-assessment"})
        for field in ("profileId", "runId", "policyDigest", "payloadDigest", "payload", "authoritySeal"):
            self.assertIn(field, schema["required"])

    def test_reconciliation_and_migration_schemas_pin_evidence_kinds(self) -> None:
        reconciliation = json.loads((ROOT / "reconciliation-state.schema.json").read_text(encoding="utf-8"))
        hint = reconciliation["properties"]["pendingHints"]["items"]
        self.assertFalse(hint.get("additionalProperties", True))
        self.assertEqual(set(hint["required"]), {"hintDigest", "eventId", "fileKey", "assetType", "eventTime"})
        migration = json.loads((ROOT / "migration-record.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(migration["properties"]["recordType"]["enum"]), {"migration_prepare", "migration_commit", "restoration_prepare", "restoration"})

if __name__ == "__main__":
    unittest.main()
