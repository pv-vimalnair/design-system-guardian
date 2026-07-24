import json
import unittest
from pathlib import Path

from tests.test_foundation_extended import EXPECTED_STATUSES


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class CanonicalSchemaTest(unittest.TestCase):
    def test_required_schema_set_exists_and_is_valid_json(self) -> None:
        expected = {
            "profile.schema.json",
            "snapshot.schema.json",
            "resolution.schema.json",
            "build-plan.schema.json",
            "audit-result.schema.json",
            "coverage.schema.json",
            "post-run-assessment.schema.json",
            "run-manifest.schema.json",
        }
        actual = {path.name for path in (PLUGIN_ROOT / "schemas").glob("*.schema.json")}
        self.assertEqual(actual, expected)
        for name in expected:
            payload = json.loads((PLUGIN_ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(payload.get("additionalProperties", True), name)

    def test_resolution_schema_enumerates_only_exact_statuses(self) -> None:
        payload = json.loads(
            (PLUGIN_ROOT / "schemas" / "resolution.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(payload["properties"]["status"]["enum"]), EXPECTED_STATUSES)

    def test_every_evidence_schema_pins_a_schema_version(self) -> None:
        for path in (PLUGIN_ROOT / "schemas").glob("*.schema.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn("schemaVersion", payload["properties"], path.name)
            self.assertIn("schemaVersion", payload["required"], path.name)
