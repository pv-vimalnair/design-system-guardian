from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
VERSION = "0.3.7"
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
SKILL_NAMES = {"audit-design-system", "build-with-design-system"}
JUDGMENT_SCHEMAS = {
    "schemas/judgment-assessment.schema.json",
    "schemas/judgment-decision-permission.schema.json",
    "schemas/judgment-effective-projection.schema.json",
    "schemas/judgment-history-head.schema.json",
    "schemas/judgment-history-record.schema.json",
}
JUDGMENT_COMMANDS = (
    "guardian judgment preview --profile <profile-id> --run-id <run-id> --input <candidate.json>",
    "guardian judgment apply --input <granted-bundle.json>",
    "guardian judgment status --profile <profile-id> --run-id <run-id>",
    "guardian judgment revoke --input <granted-revocation.json>",
)
PUBLIC_PAGES = (
    REPOSITORY_ROOT / "README.md",
    PLUGIN_ROOT / "README.md",
    PLUGIN_ROOT / "CHANGELOG.md",
    PLUGIN_ROOT / "SECURITY.md",
    PLUGIN_ROOT / "docs" / "INSTALLING.md",
    PLUGIN_ROOT / "docs" / "UPDATING.md",
    PLUGIN_ROOT / "docs" / "RELEASES.md",
    PLUGIN_ROOT / "docs" / "TRUSTED_EXECUTION.md",
)


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class V037PublicContractTest(unittest.TestCase):
    def test_every_public_version_surface_is_exactly_v037(self) -> None:
        marketplace = _json(REPOSITORY_ROOT / ".claude-plugin" / "marketplace.json")
        manifests = (
            _json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"),
            _json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json"),
            _json(REPOSITORY_ROOT / "kimi.plugin.json"),
            marketplace["plugins"][0],
        )
        self.assertTrue(all(manifest["version"] == VERSION for manifest in manifests))

        from guardian_core.release import RUNTIME_VERSION

        self.assertEqual(RUNTIME_VERSION, VERSION)
        pubspec = (PLUGIN_ROOT / "adapters/flutter/pubspec.yaml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(pubspec, rf"(?m)^version: {re.escape(VERSION)}$")

    def test_two_skills_policy_and_v037_schema_additions_are_preserved(self) -> None:
        skills = {
            path.name
            for path in (PLUGIN_ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(skills, SKILL_NAMES)

        policy = _json(PLUGIN_ROOT / "policy/policy-v1.json")
        canonical = json.dumps(
            policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), POLICY_DIGEST)

        schemas = {
            path.relative_to(PLUGIN_ROOT).as_posix()
            for path in PLUGIN_ROOT.rglob("*.schema.json")
        }
        self.assertEqual(len(schemas), 43)
        self.assertTrue(JUDGMENT_SCHEMAS.issubset(schemas))

    def test_skills_explain_the_exact_run_judgment_flow(self) -> None:
        common = (
            "explain every finding",
            "raw findings",
            "effective",
            "optional reason",
            "every new screen or flow",
            "never reuse",
            "duplicate file",
            "Usage Rules",
            "sentinel",
            "stale",
            "source_incomplete",
            "unsupported",
            "not_assessed",
            "protected-authority",
        )
        for name in SKILL_NAMES:
            skill = (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            with self.subTest(skill=name):
                for phrase in common:
                    self.assertIn(phrase, skill)
                for command in JUDGMENT_COMMANDS:
                    self.assertIn(command, skill)

        build = (
            PLUGIN_ROOT / "skills/build-with-design-system/SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Fix and evaluate again", build)
        self.assertIn("Approve this exact version anyway", build)

        audit = (PLUGIN_ROOT / "skills/audit-design-system/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("preview and status are read-only", audit)
        self.assertIn("separate permission", audit)

    def test_ux_decision_record_refreshes_canonical_judgment_status(self) -> None:
        record = (
            PLUGIN_ROOT
            / "skills/build-with-design-system/references/ux-decision-record.md"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Update product-intent content only when product intent changes.",
            record,
        )
        self.assertIn(JUDGMENT_COMMANDS[2], record)
        self.assertIn(
            "whenever canonical judgment state changes, including apply or revoke",
            record,
        )

    def test_public_docs_cover_portable_hosts_privacy_and_compatibility(self) -> None:
        joined = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_PAGES)
        for command in JUDGMENT_COMMANDS:
            self.assertIn(command, joined)
        for phrase in (
            "Codex",
            "Claude Code",
            "OpenClaw",
            "Kimi Code",
            "Qwen Code",
            "generic Agent Skills",
            "v0.3.6",
            "synthetic",
            "assessments, reasons, decisions",
            "never enter Git, Elo, or telemetry",
            "cannot prevent raw-tool bypass",
            "read back",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, joined)

        changelog = (PLUGIN_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        positions = [changelog.index(f"## 0.3.{minor}") for minor in range(7, 1, -1)]
        self.assertEqual(positions, sorted(positions))

    def test_current_public_docs_contain_no_absolute_local_path(self) -> None:
        forbidden = (
            re.compile(r"[A-Za-z]:\\(?:Users|Documents|tmp)\\"),
            re.compile(r"/(?:Users|home)/[^/\s]+/"),
        )
        for page in PUBLIC_PAGES:
            text = page.read_text(encoding="utf-8")
            with self.subTest(page=page.relative_to(REPOSITORY_ROOT).as_posix()):
                for pattern in forbidden:
                    self.assertIsNone(pattern.search(text))

    def test_ci_keeps_prior_suites_and_adds_focused_v037_validation(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("os: [windows-latest, ubuntu-latest]"), 2)
        self.assertIn("39a2438d16514d0d6f88105d17b0f747994af487", workflow)
        self.assertIn("python scripts/check_public_release.py", workflow)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py"', workflow)
        self.assertIn("tests.test_v037_public_contract", workflow)
        self.assertIn("tests.test_cli_judgment_dsg027", workflow)
        self.assertIn("assert len(schemas) == 43", workflow)


if __name__ == "__main__":
    unittest.main()
