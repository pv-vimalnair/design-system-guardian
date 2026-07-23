from __future__ import annotations

import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PLUGIN_ROOT / "schemas" / "release"
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"


class ReleaseSchemaTest(unittest.TestCase):
    def test_exact_release_schema_set_is_strict_draft_2020_12(self) -> None:
        expected = {
            "external-release-head.schema.json",
            "release-authority-binding.schema.json",
            "release-channel-state.schema.json",
            "release-history-record.schema.json",
            "release-manifest.schema.json",
        }
        self.assertEqual({path.name for path in SCHEMA_ROOT.glob("*.schema.json")}, expected)
        for name in expected:
            schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(schema.get("additionalProperties", True), name)
            self.assertIn("schemaVersion", schema["required"])
            self.assertEqual(schema["properties"]["schemaVersion"], {"const": 1})

    def test_manifest_schema_pins_policy_commit_channels_and_signature(self) -> None:
        schema = json.loads(
            (SCHEMA_ROOT / "release-manifest.schema.json").read_text(encoding="utf-8")
        )
        properties = schema["properties"]
        self.assertEqual(properties["pluginName"], {"const": "design-system-guardian"})
        self.assertEqual(properties["policyDigest"], {"const": POLICY_DIGEST})
        self.assertEqual(set(properties["channel"]["enum"]), {"canary", "stable"})
        self.assertIn("{40}", properties["sourceCommit"]["pattern"])
        self.assertIn("{64}", properties["sourceCommit"]["pattern"])
        authority = properties["authority"]
        self.assertFalse(authority["additionalProperties"])
        self.assertEqual(authority["properties"]["algorithm"], {"const": "ed25519"})
        self.assertEqual(set(schema["allOf"][0]["then"]["properties"]), {"reason", "targetManifestDigest"})

    def test_external_head_schema_requires_signed_chain_and_stable_canary_checkpoint(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError as error:  # pragma: no cover - required test dependency
            self.fail(f"jsonschema is required: {error}")
        schema = json.loads(
            (SCHEMA_ROOT / "external-release-head.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        properties = schema["properties"]
        self.assertEqual(properties["pluginName"], {"const": "design-system-guardian"})
        self.assertEqual(properties["policyDigest"], {"const": POLICY_DIGEST})
        self.assertEqual(set(properties["channel"]["enum"]), {"canary", "stable"})
        self.assertIn("historyEventDigest", schema["required"])
        self.assertIn("previousCheckpointDigest", schema["required"])
        self.assertIn("canaryCheckpointDigest", schema["required"])
        authority = properties["authority"]
        self.assertFalse(authority["additionalProperties"])
        self.assertEqual(authority["properties"]["algorithm"], {"const": "ed25519"})
        self.assertEqual(len(schema["allOf"]), 3)

    def test_release_docs_state_real_promotion_blocker_and_verifier_only_boundary(self) -> None:
        for name in ("README.md", "SECURITY.md", "CHANGELOG.md"):
            self.assertTrue((PLUGIN_ROOT / name).is_file(), name)
        for name in ("UPDATING.md", "RELEASES.md"):
            self.assertTrue((PLUGIN_ROOT / "docs" / name).is_file(), name)
        security = (PLUGIN_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        changelog = (PLUGIN_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        updating = (PLUGIN_ROOT / "docs" / "UPDATING.md").read_text(encoding="utf-8")
        self.assertIn("private key must remain", security)
        self.assertIn("Not promoted", changelog)
        self.assertIn("external authority", updating)
        self.assertIn(POLICY_DIGEST, updating)


if __name__ == "__main__":
    unittest.main()
