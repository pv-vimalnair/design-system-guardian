from __future__ import annotations

import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class SafeActivationSkillContractTest(unittest.TestCase):
    def test_both_skills_explain_safe_activation_and_deferred_coverage(self) -> None:
        required = (
            "guardian rules activate preview",
            "guardian rules activate apply",
            "permission enables the evaluator",
            "does not approve rules",
            "externally signed catalog",
            "compilation_unit",
            "not_assessed",
            "never fall back",
            "v0.3.6",
        )
        for name in ("build-with-design-system", "audit-design-system"):
            text = (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            ).lower()
            with self.subTest(skill=name):
                for phrase in required:
                    self.assertIn(phrase, text)

    def test_pressure_cases_separate_permission_from_approval_and_deferred_scope(self) -> None:
        payload = json.loads(
            (PLUGIN_ROOT / "tests" / "skill_pressure_cases.json").read_text(
                encoding="utf-8"
            )
        )
        prompts = "\n".join(case["prompt"].lower() for case in payload["cases"])
        self.assertIn("permission means the rules are approved", prompts)
        self.assertIn("widget_class", prompts)
        cases = {case["id"]: case for case in payload["cases"]}
        self.assertEqual(
            cases["permission-is-not-rule-approval"]["expectedStatus"],
            "invalid",
        )
        self.assertEqual(
            cases["deferred-widget-class-rule"]["expectedStatus"],
            "not_assessed",
        )


if __name__ == "__main__":
    unittest.main()
