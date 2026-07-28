from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
SKILL_NAMES = {"audit-design-system", "build-with-design-system"}
V036_SCHEMA_INVENTORY = {
    "adapters/figma/contracts/figma-observation.schema.json",
    "adapters/flutter/contracts/flutter-adapter-config-v2.schema.json",
    "adapters/flutter/contracts/flutter-adapter-config-v3.schema.json",
    "adapters/flutter/contracts/flutter-adapter-config.schema.json",
    "adapters/flutter/contracts/flutter-adapter-result-v2.schema.json",
    "adapters/flutter/contracts/flutter-adapter-result.schema.json",
    "adapters/flutter/contracts/suppression-scan.schema.json",
    "schemas/audit-result-v2.schema.json",
    "schemas/audit-result.schema.json",
    "schemas/build-plan.schema.json",
    "schemas/coverage.schema.json",
    "schemas/evaluator-authorization-pointer.schema.json",
    "schemas/evaluator-authorization-record.schema.json",
    "schemas/evaluator-upgrade-permission.schema.json",
    "schemas/evolution/elo-benchmark-result.schema.json",
    "schemas/evolution/elo-ledger-entry.schema.json",
    "schemas/lifecycle/analysis-attestation.schema.json",
    "schemas/lifecycle/migration-record.schema.json",
    "schemas/lifecycle/reconciliation-state.schema.json",
    "schemas/lifecycle/sealed-run-artifact.schema.json",
    "schemas/post-run-assessment-v2.schema.json",
    "schemas/post-run-assessment.schema.json",
    "schemas/profile.schema.json",
    "schemas/release/external-release-head.schema.json",
    "schemas/release/release-authority-binding.schema.json",
    "schemas/release/release-channel-state.schema.json",
    "schemas/release/release-history-record.schema.json",
    "schemas/release/release-manifest.schema.json",
    "schemas/resolution.schema.json",
    "schemas/rule-activation-permission.schema.json",
    "schemas/rule-activation-snapshot.schema.json",
    "schemas/rule.schema.json",
    "schemas/rules-list.schema.json",
    "schemas/rules-validation-report.schema.json",
    "schemas/run-manifest-v2.schema.json",
    "schemas/run-manifest.schema.json",
    "schemas/snapshot.schema.json",
    "schemas/usage-rules-evidence.schema.json",
}


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class V036PublicContractTest(unittest.TestCase):
    def test_public_manifest_shape_and_license_remain_compatible(self) -> None:
        claude_marketplace = _json(
            REPOSITORY_ROOT / ".claude-plugin" / "marketplace.json"
        )
        marketplace_plugins = claude_marketplace["plugins"]
        self.assertIsInstance(marketplace_plugins, list)
        self.assertEqual(len(marketplace_plugins), 1)

        manifests = {
            "claude-marketplace": marketplace_plugins[0],
            "kimi": _json(REPOSITORY_ROOT / "kimi.plugin.json"),
            "codex": _json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"),
            "claude": _json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json"),
        }
        versions = set()
        for host, manifest in manifests.items():
            with self.subTest(host=host):
                self.assertEqual(manifest["name"], "design-system-guardian")
                self.assertRegex(manifest["version"], r"^0\.3\.[0-9]+$")
                self.assertEqual(manifest["license"], "MIT")
                versions.add(manifest["version"])
        self.assertEqual(len(versions), 1)

        self.assertEqual(
            {manifest["description"] for manifest in manifests.values()},
            {
                "Requires explicit per-task and per-Figma-file library selection, "
                "then enforces exact approved design-system identities with Figma "
                "read-back, UX checks, preview-only rule validation, "
                "permission-bound machine-rule evaluation, exact-run judgment exceptions, and fail-closed evidence."
            },
        )
        self.assertEqual(manifests["codex"]["skills"], "./skills/")
        self.assertEqual(manifests["claude"]["skills"], "./skills/")
        self.assertEqual(
            manifests["kimi"]["skills"],
            "./plugins/design-system-guardian/skills/",
        )

        codex_marketplace = _json(
            REPOSITORY_ROOT / ".agents" / "plugins" / "marketplace.json"
        )
        self.assertEqual(len(codex_marketplace["plugins"]), 1)
        self.assertEqual(
            codex_marketplace["plugins"][0]["source"],
            {"source": "local", "path": "./plugins/design-system-guardian"},
        )

    def test_package_exposes_exactly_two_canonical_agent_skills(self) -> None:
        skills = {
            path.name
            for path in (PLUGIN_ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(skills, SKILL_NAMES)
        self.assertEqual(
            {
                path.relative_to(PLUGIN_ROOT).as_posix()
                for path in PLUGIN_ROOT.rglob("SKILL.md")
            },
            {f"skills/{name}/SKILL.md" for name in SKILL_NAMES},
        )
        for name in SKILL_NAMES:
            skill = (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            self.assertTrue(skill.startswith(f"---\nname: {name}\n"), name)

    def test_immutable_policy_digest_is_unchanged(self) -> None:
        policy = _json(PLUGIN_ROOT / "policy" / "policy-v1.json")
        canonical = json.dumps(
            policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), POLICY_DIGEST)

    def test_skills_and_release_pages_explain_the_v036_boundary(self) -> None:
        required_skill_phrases = (
            "guardian rules list",
            "guardian rules upgrade preview",
            "guardian rules upgrade apply",
            "plain language",
            "Usage Rules",
            "reload_required",
            "host_restart_required",
            "Never fall back",
        )
        for name in SKILL_NAMES:
            text = (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            with self.subTest(skill=name):
                for phrase in required_skill_phrases:
                    self.assertIn(phrase, text)

        pages = (
            REPOSITORY_ROOT / "README.md",
            PLUGIN_ROOT / "README.md",
            PLUGIN_ROOT / "CHANGELOG.md",
            PLUGIN_ROOT / "docs" / "INSTALLING.md",
            PLUGIN_ROOT / "docs" / "UPDATING.md",
            PLUGIN_ROOT / "docs" / "RELEASES.md",
        )
        for page in pages:
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.name):
                self.assertIn("0.3.6", text)
                self.assertIn("guardian rules list", text)
                self.assertIn("Usage Rules", text)
                self.assertIn("reload_required", text)
                self.assertIn("host_restart_required", text)

        changelog = (PLUGIN_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertLess(changelog.index("## 0.3.6"), changelog.index("## 0.3.5"))
        self.assertLess(changelog.index("## 0.3.5"), changelog.index("## 0.3.4"))

    def test_v036_schema_inventory_remains_available_and_json_parses(self) -> None:
        actual = {
            path.relative_to(PLUGIN_ROOT).as_posix()
            for path in PLUGIN_ROOT.rglob("*.schema.json")
        }
        self.assertGreaterEqual(len(actual), len(V036_SCHEMA_INVENTORY))
        self.assertTrue(V036_SCHEMA_INVENTORY.issubset(actual))
        for relative in sorted(actual):
            with self.subTest(schema=relative):
                _json(PLUGIN_ROOT / relative)


if __name__ == "__main__":
    unittest.main()
