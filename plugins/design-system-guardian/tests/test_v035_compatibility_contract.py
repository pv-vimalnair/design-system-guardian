from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"


class V035CompatibilityContractTest(unittest.TestCase):
    def test_immutable_policy_and_two_skill_surface_are_unchanged(self) -> None:
        policy = PLUGIN_ROOT / "policy" / "policy-v1.json"
        canonical = json.dumps(
            json.loads(policy.read_text(encoding="utf-8")),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), POLICY_DIGEST)
        skills = sorted(
            path.name
            for path in (PLUGIN_ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        )
        self.assertEqual(skills, ["audit-design-system", "build-with-design-system"])

    def test_all_legacy_schema_contracts_remain_and_v1_contracts_stay_explicit(self) -> None:
        legacy = {
            "adapters/figma/contracts/figma-observation.schema.json",
            "adapters/flutter/contracts/flutter-adapter-config.schema.json",
            "adapters/flutter/contracts/flutter-adapter-result.schema.json",
            "adapters/flutter/contracts/suppression-scan.schema.json",
            "schemas/audit-result.schema.json",
            "schemas/build-plan.schema.json",
            "schemas/coverage.schema.json",
            "schemas/evolution/elo-benchmark-result.schema.json",
            "schemas/evolution/elo-ledger-entry.schema.json",
            "schemas/lifecycle/analysis-attestation.schema.json",
            "schemas/lifecycle/migration-record.schema.json",
            "schemas/lifecycle/reconciliation-state.schema.json",
            "schemas/lifecycle/sealed-run-artifact.schema.json",
            "schemas/post-run-assessment.schema.json",
            "schemas/profile.schema.json",
            "schemas/release/external-release-head.schema.json",
            "schemas/release/release-authority-binding.schema.json",
            "schemas/release/release-channel-state.schema.json",
            "schemas/release/release-history-record.schema.json",
            "schemas/release/release-manifest.schema.json",
            "schemas/resolution.schema.json",
            "schemas/rule.schema.json",
            "schemas/rules-validation-report.schema.json",
            "schemas/run-manifest.schema.json",
            "schemas/snapshot.schema.json",
        }
        self.assertTrue(all((PLUGIN_ROOT / relative).is_file() for relative in legacy))
        profile = json.loads(
            (PLUGIN_ROOT / "schemas/profile.schema.json").read_text(encoding="utf-8")
        )
        snapshot = json.loads(
            (PLUGIN_ROOT / "schemas/snapshot.schema.json").read_text(encoding="utf-8")
        )
        flutter_v1 = json.loads(
            (
                PLUGIN_ROOT
                / "adapters/flutter/contracts/flutter-adapter-config.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(profile["properties"]["schemaVersion"], {"const": 1})
        self.assertEqual(snapshot["properties"]["schemaVersion"], {"const": 1})
        self.assertEqual(flutter_v1["properties"]["schemaVersion"], {"const": 1})

    def test_v035_adds_contracts_without_replacing_legacy_contracts(self) -> None:
        additions = {
            "schemas/rule-activation-permission.schema.json",
            "schemas/rule-activation-snapshot.schema.json",
            "adapters/flutter/contracts/flutter-adapter-config-v2.schema.json",
        }
        self.assertTrue(all((PLUGIN_ROOT / relative).is_file() for relative in additions))
        schemas = sorted(PLUGIN_ROOT.rglob("*.schema.json"))
        # The exact v0.3.5 count remains executable from its public tag through
        # the release-inheritance harness; newer releases may only add schemas.
        self.assertGreaterEqual(len(schemas), 28)
        for path in schemas:
            json.loads(path.read_text(encoding="utf-8"))

    def test_every_public_host_manifest_is_v035_and_mit(self) -> None:
        manifests = (
            REPOSITORY_ROOT / ".claude-plugin/marketplace.json",
            REPOSITORY_ROOT / "kimi.plugin.json",
            PLUGIN_ROOT / ".codex-plugin/plugin.json",
            PLUGIN_ROOT / ".claude-plugin/plugin.json",
        )
        rendered = "\n".join(path.read_text(encoding="utf-8") for path in manifests)
        self.assertNotIn('"version": "0.3.4"', rendered)
        for path in manifests:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(
                "0.3.5" in text or "0.3.6" in text or "0.3.7" in text,
                path,
            )
        plugin = json.loads(
            (PLUGIN_ROOT / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
        )
        self.assertEqual(plugin["license"], "MIT")


if __name__ == "__main__":
    unittest.main()
