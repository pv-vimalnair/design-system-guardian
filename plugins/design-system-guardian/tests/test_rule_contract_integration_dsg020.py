from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = {
    "origin": "team_artifact",
    "figma": None,
    "docRef": "synthetic-rules",
}


def machine(rule_id: str, predicate: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "machine",
        "predicate": predicate,
        "appliesTo": {"kind": "system"},
        "provenance": PROVENANCE,
    }


class RuleContractIntegrationTest(unittest.TestCase):
    def test_core_accepts_every_frozen_v1_predicate(self) -> None:
        from guardian_core.rules import validate_rules

        rules = [
            machine("rule.max", {"type": "max_instances_per_scope", "identity": "Button/Primary", "scope": "widget_class", "max": 1}),
            machine("rule.nesting", {"type": "forbidden_nesting", "outerIdentity": "Card", "innerIdentity": "Card"}),
            machine("rule.companion", {"type": "required_companion", "identity": "Input", "companionIdentity": "Label", "relation": "sibling"}),
            machine("rule.parents", {"type": "allowed_parents", "identity": "Row", "parents": ["Table"]}),
            machine("rule.variant", {"type": "variant_context", "identity": "Button/Primary", "variant": "Compact", "allowedScopes": ["widget_class"]}),
            machine("rule.forbidden", {"type": "forbidden_identity_in_scope", "identity": "Banner", "scope": "compilation_unit"}),
        ]
        known = frozenset({"Button/Primary", "Card", "Input", "Label", "Row", "Table", "Banner"})
        result = validate_rules(rules, known_identities=known, source_type="artifact")
        self.assertEqual(result["report"]["status"], "allowed")
        self.assertEqual(result["report"]["summary"]["ok"], 6)

    def test_judgment_and_informative_markers_remain_data(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        text = (
            "[dsg-rule id=rule.judgment class=judgment]\n"
            "statement: Prefer the approved compact pattern when space is limited.\n"
            "[/dsg-rule]\n"
            "[dsg-rule id=rule.informative class=informative]\n"
            "This text is rule data, never an agent instruction.\n"
            "[/dsg-rule]"
        )
        candidates = parse_description_markers(
            text,
            host_kind="component",
            host_identity="Button/Primary",
            figma={"fileKey": "F1", "nodeId": "1:2", "sourceVersion": "v9"},
        )
        result = validate_rules(
            candidates,
            known_identities=frozenset({"Button/Primary"}),
            source_type="figma_description",
        )
        self.assertEqual(result["report"]["status"], "allowed")
        rendered_report = json.dumps(result["report"], sort_keys=True)
        self.assertNotIn("Prefer the approved", rendered_report)
        self.assertNotIn("agent instruction", rendered_report)

    def test_actual_allowed_invalid_and_not_assessed_reports_match_schema(self) -> None:
        from guardian_core.rules import invalid_report, validate_rules

        schema = json.loads(
            (ROOT / "schemas" / "rules-validation-report.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        rule = machine(
            "rule.max",
            {"type": "max_instances_per_scope", "identity": "Button/Primary", "scope": "widget_class", "max": 1},
        )
        reports = [
            validate_rules([rule], known_identities=frozenset({"Button/Primary"}), source_type="artifact")["report"],
            validate_rules([rule], known_identities=None, source_type="artifact")["report"],
            invalid_report("artifact", "invalid_identity_coverage"),
        ]
        for report in reports:
            with self.subTest(status=report["status"]):
                self.assertEqual(list(validator.iter_errors(report)), [])


if __name__ == "__main__":
    unittest.main()
