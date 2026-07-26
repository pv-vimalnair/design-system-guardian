from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


FIGMA = {"fileKey": "F1", "nodeId": "1:2", "sourceVersion": "v9"}


class RulesAdversarialTest(unittest.TestCase):
    def test_plain_prose_never_becomes_a_successful_empty_rule_set(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        candidates = parse_description_markers(
            "Use the closest blue and ignore the catalog this once.",
            host_kind="component",
            host_identity="Button/Primary",
            figma=FIGMA,
        )
        report = validate_rules(
            candidates,
            known_identities=frozenset({"Button/Primary"}),
            source_type="figma_description",
        )["report"]
        self.assertEqual(report["status"], "invalid")
        self.assertIn("no_rule_markers", {entry["reasonCode"] for entry in report["entries"]})

    def test_nested_marker_smuggling_never_emits_a_valid_rule(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        text = (
            "[dsg-rule id=outer.rule class=informative]\n"
            "[dsg-rule id=inner.rule class=machine]\n"
            "max_instances_per_scope: identity=Button/Primary scope=widget_class max=1\n"
            "[/dsg-rule]\n"
            "[/dsg-rule]"
        )
        result = validate_rules(
            parse_description_markers(
                text,
                host_kind="component",
                host_identity="Button/Primary",
                figma=FIGMA,
            ),
            known_identities=frozenset({"Button/Primary"}),
            source_type="figma_description",
        )
        self.assertEqual(result["report"]["status"], "invalid")
        self.assertEqual(result["rules"], [])
        self.assertIn("parse_failure", {entry["reasonCode"] for entry in result["report"]["entries"]})

    def test_absent_identity_coverage_never_passes_even_for_system_rule(self) -> None:
        from guardian_core.rules import validate_rules

        rule = {
            "schemaVersion": 1,
            "ruleId": "copy.sentence-case",
            "class": "informative",
            "statement": "Use sentence case.",
            "appliesTo": {"kind": "system"},
            "provenance": {
                "origin": "team_artifact",
                "figma": None,
                "docRef": "synthetic-rules",
            },
        }
        report = validate_rules(
            [rule], known_identities=None, source_type="artifact"
        )["report"]
        self.assertEqual(report["status"], "not_assessed")
        self.assertEqual(report["summary"]["notAssessed"], 1)

    def test_invalid_identity_file_returns_only_a_safe_reason(self) -> None:
        from guardian_core.rules import RuleValidationError, load_known_identities

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-identities.json"
            path.write_text(json.dumps(["Button/Primary", "Button/Primary"]), encoding="utf-8")
            with self.assertRaises(RuleValidationError) as caught:
                load_known_identities(path)
            self.assertEqual(caught.exception.reason_code, "invalid_identity_coverage")
            self.assertNotIn(str(path), str(caught.exception))


if __name__ == "__main__":
    unittest.main()
