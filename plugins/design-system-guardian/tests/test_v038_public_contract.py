from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT.parents[1]
VERSION = "0.3.8"
V037_BASE = "4d0615f0c7dabc480f71144bacdca8689bb66059"
POLICY_DIGEST = "3bf2913583cee2d791aed5093bc1df905b26dcdbb0c4d945f0ae5b2eddaaa99f"
SKILLS = {"audit-design-system", "build-with-design-system"}
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

AUTHORITY_BOUNDARY_PAGES = (
    PLUGIN_ROOT / "SECURITY.md",
    PLUGIN_ROOT / "adapters" / "figma" / "README.md",
    PLUGIN_ROOT / "docs" / "INSTALLING.md",
    PLUGIN_ROOT / "docs" / "UPDATING.md",
)
SELECTION_COMMANDS = (
    "guardian selection status --run-id <run-id>",
    "guardian selection preview --run-id <run-id> --input <discovery.json>",
    "guardian selection apply --input <permission-bound-selection.json>",
)


def _json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class V038PublicContractTest(unittest.TestCase):
    def test_exact_version_policy_and_two_skill_surface(self) -> None:
        marketplace = _json(REPOSITORY_ROOT / ".claude-plugin" / "marketplace.json")
        manifests = (
            _json(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"),
            _json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json"),
            _json(REPOSITORY_ROOT / "kimi.plugin.json"),
            marketplace["plugins"][0],
        )
        self.assertTrue(all(item["version"] == VERSION for item in manifests))

        from guardian_core.release import RUNTIME_VERSION

        self.assertEqual(RUNTIME_VERSION, VERSION)
        self.assertIn(
            f"version: {VERSION}",
            (PLUGIN_ROOT / "adapters/flutter/pubspec.yaml").read_text(
                encoding="utf-8"
            ),
        )
        skills = {
            path.name
            for path in (PLUGIN_ROOT / "skills").iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(skills, SKILLS)

        policy = _json(PLUGIN_ROOT / "policy/policy-v1.json")
        canonical = json.dumps(
            policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), POLICY_DIGEST)

    def test_personal_selection_schema_is_additive_and_strict(self) -> None:
        schemas = sorted(PLUGIN_ROOT.rglob("*.schema.json"))
        self.assertEqual(len(schemas), 44)
        selection = _json(
            PLUGIN_ROOT / "schemas/design-system-selection.schema.json"
        )
        self.assertEqual(selection["properties"]["schemaVersion"], {"const": 1})
        self.assertEqual(
            selection["properties"]["authorityMode"],
            {"const": "personal_local"},
        )
        self.assertEqual(
            selection["properties"]["policyDigest"],
            {"const": POLICY_DIGEST},
        )
        self.assertIn("catalogReadbackDigest", selection["required"])
        self.assertEqual(
            selection["properties"]["catalogReadbackDigest"],
            {"$ref": "#/$defs/digest"},
        )

        snapshot = _json(PLUGIN_ROOT / "schemas/snapshot.schema.json")
        alternatives = snapshot["$defs"]["catalogApprovalAttestation"]["oneOf"]
        references = {item["$ref"] for item in alternatives}
        self.assertEqual(
            references,
            {
                "#/$defs/approvalAttestation",
                "#/$defs/personalApprovalAttestation",
            },
        )
        self.assertEqual(
            snapshot["$defs"]["approvalAttestation"]["properties"]["algorithm"],
            {"const": "ed25519"},
        )
        self.assertEqual(
            snapshot["$defs"]["personalApprovalAttestation"]["properties"][
                "algorithm"
            ],
            {"const": "hmac-sha256"},
        )

    def test_cli_exposes_only_the_three_personal_selection_commands(self) -> None:
        from guardian_core.cli import build_parser

        parser = build_parser()
        command_action = next(
            action
            for action in parser._actions
            if getattr(action, "dest", None) == "command"
        )
        selection = command_action.choices["selection"]
        selection_action = next(
            action
            for action in selection._actions
            if getattr(action, "dest", None) == "selection_command"
        )
        self.assertEqual(
            set(selection_action.choices),
            {"status", "preview", "apply"},
        )

    def test_both_skills_require_fresh_explicit_use_and_do_not_use_selection(self) -> None:
        common = (
            "personal-local",
            "**Use**",
            "**Do not use**",
            "every new",
            "zero-library",
            "never reuse",
            "Every **Do not use** library is forbidden",
            "enterprise",
            "exactly these two skills",
            "catalogReadback",
            "one-to-one",
            "token content",
            "Code Connect",
        )
        for name in SKILLS:
            text = (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            with self.subTest(skill=name):
                for phrase in common:
                    self.assertIn(phrase, text)
                for command in SELECTION_COMMANDS:
                    self.assertIn(command, text)

    def test_public_docs_cover_personal_privacy_and_every_supported_host(self) -> None:
        joined = "\n".join(path.read_text(encoding="utf-8") for path in PUBLIC_PAGES)
        for phrase in (
            "0.3.8",
            "personal-local",
            "**Use**",
            "**Do not use**",
            "every unselected library is forbidden",
            "Codex",
            "Claude Code",
            "OpenClaw",
            "Kimi Code",
            "Qwen Code",
            "generic Agent Skills",
            "never enter Git",
            "enterprise",
            "catalog read-back",
            "one-to-one",
            "unprotected_caller_carried",
            "resolved content digest",
            "design-contract digest",
            "Code Connect mapping digest",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, joined)
        for command in SELECTION_COMMANDS:
            self.assertIn(command, joined)

    def test_current_authority_docs_keep_personal_local_and_protected_lanes_separate(self) -> None:
        for path in AUTHORITY_BOUNDARY_PAGES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("personal_local", text)
                self.assertIn("not_assessed", text)
                self.assertIn("caller", text.lower())
                self.assertIn("production", text.lower())
                self.assertNotIn(
                    "may be `allowed` for local design-system coverage",
                    text,
                )

    def test_v037_is_the_exact_ancestor_and_v8_elo_is_append_only(self) -> None:
        completed = subprocess.run(
            ["git", "merge-base", "HEAD", V037_BASE],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), V037_BASE)

        suite = _json(PLUGIN_ROOT / "benchmarks/elo-suite.json")
        current = _json(PLUGIN_ROOT / "benchmarks/current-score.json")
        self.assertEqual(suite["suiteVersion"], 8)
        self.assertEqual(
            suite["caseModules"][-1]["moduleId"],
            "guardian-public-cases-v8",
        )
        self.assertEqual(current["score"], 1)
        self.assertEqual(current["suiteSnapshot"]["suiteVersion"], 3)

    def test_ci_keeps_all_prior_tests_and_focuses_v038(self) -> None:
        workflow = (
            REPOSITORY_ROOT / ".github/workflows/validate.yml"
        ).read_text(encoding="utf-8")
        for module in (
            "tests.test_v037_public_contract",
            "tests.test_v038_public_contract",
            "tests.test_personal_selection_dsg028",
            "tests.test_personal_selection_adversarial_dsg028",
            "tests.test_personal_trust_dsg028",
            "tests.test_cli_personal_selection_dsg028",
            "tests.test_figma_personal_selection_dsg028",
            "tests.test_flutter_personal_pin_dsg028",
            "tests.test_publication_personal_privacy_dsg028",
            "tests.test_weighted_elo_v8",
        ):
            self.assertIn(module, workflow)
        self.assertIn("assert len(schemas) >= 43", workflow)


if __name__ == "__main__":
    unittest.main()
