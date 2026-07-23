from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = PLUGIN_ROOT / "skills"


def skill_text(name: str) -> str:
    return (SKILLS_ROOT / name / "SKILL.md").read_text(encoding="utf-8")


class VisibleSkillContractTest(unittest.TestCase):
    def test_plugin_exposes_exactly_two_skill_directories(self) -> None:
        visible = {
            path.name
            for path in SKILLS_ROOT.iterdir()
            if path.is_dir() and (path / "SKILL.md").is_file()
        }
        self.assertEqual(
            visible,
            {"build-with-design-system", "audit-design-system"},
        )

    def test_skill_frontmatter_is_portable_and_complete(self) -> None:
        for name in ("build-with-design-system", "audit-design-system"):
            with self.subTest(skill=name):
                text = skill_text(name)
                match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
                self.assertIsNotNone(match)
                frontmatter = match.group(1)
                keys = {
                    line.split(":", 1)[0]
                    for line in frontmatter.splitlines()
                    if ":" in line
                }
                self.assertEqual(keys, {"name", "description"})
                self.assertIn(f"name: {name}", frontmatter)
                self.assertNotRegex(text, r"\bTODO\b|\[TODO")

    def test_both_skills_state_the_non_overridable_exact_identity_contract(self) -> None:
        required = (
            "only exact, explicitly approved identities",
            "deny always wins",
            "closest",
            "equal-value",
            "framework defaults",
            "generated icons",
            "manual recreation",
            "name-based guessing",
            "stop the task",
        )
        for name in ("build-with-design-system", "audit-design-system"):
            lowered = skill_text(name).lower()
            with self.subTest(skill=name):
                for phrase in required:
                    self.assertIn(phrase, lowered)

    def test_build_skill_encodes_pinned_fail_closed_workflow(self) -> None:
        text = skill_text("build-with-design-system").lower()
        for phrase in (
            "guardian doctor",
            "guardian preflight",
            "--project-root",
            "authority-bound",
            "guardian resolve",
            "guardian audit",
            "guardian finalize",
            "one pinned snapshot",
            "ux decision record",
            "source_unavailable",
            "source_incomplete",
            "productionready=false",
            "normal product copy",
            "figma search is discovery only",
        ):
            self.assertIn(phrase, text)
        for label in ("MISSING ICON", "MISSING COLOR", "MISSING TEXT STYLE"):
            self.assertIn(label, skill_text("build-with-design-system"))

    def test_audit_skill_is_read_only_and_never_turns_unknown_into_pass(self) -> None:
        text = skill_text("audit-design-system").lower()
        for phrase in (
            "read-only",
            "do not edit",
            "not_assessed",
            "incomplete coverage",
            "separate lanes",
            "design-system gap",
            "unsupported",
            "equal-looking raw values",
        ):
            self.assertIn(phrase, text)

    def test_pressure_cases_cover_override_attempts_and_distinct_source_states(self) -> None:
        payload = json.loads(
            (PLUGIN_ROOT / "tests" / "skill_pressure_cases.json").read_text(
                encoding="utf-8"
            )
        )
        prompts = "\n".join(case["prompt"].lower() for case in payload["cases"])
        for pressure in (
            "closest blue",
            "material icon",
            "ignore the catalog",
            "same hex",
            "figma is unavailable",
            "published variables have no values",
        ):
            self.assertIn(pressure, prompts)
        self.assertEqual(
            {case["expectedStatus"] for case in payload["cases"]},
            {
                "invalid",
                "not_assessed",
                "source_unavailable",
                "source_incomplete",
            },
        )


if __name__ == "__main__":
    unittest.main()
