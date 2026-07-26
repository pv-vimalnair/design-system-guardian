from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


FIGMA = {"fileKey": "F1", "nodeId": "1:2", "sourceVersion": "v9"}
MACHINE_RULE = {
    "schemaVersion": 1,
    "ruleId": "button-primary.max-per-widget",
    "class": "machine",
    "predicate": {
        "type": "max_instances_per_scope",
        "identity": "Button/Primary",
        "scope": "widget_class",
        "max": 1,
    },
    "appliesTo": {"kind": "component", "identity": "Button/Primary"},
    "provenance": {"origin": "figma_description", "figma": FIGMA, "docRef": None},
}


class RuleFoundationSchemaTest(unittest.TestCase):
    def test_rule_and_report_schemas_are_strict_draft_2020_12(self) -> None:
        for name in ("rule.schema.json", "rules-validation-report.schema.json"):
            payload = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertFalse(payload["additionalProperties"])
            Draft202012Validator.check_schema(payload)

    def test_rule_schema_accepts_all_six_predicates_and_rejects_unknown_fields(self) -> None:
        schema = json.loads((SCHEMAS / "rule.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        predicates = (
            {"type": "max_instances_per_scope", "identity": "Button/Primary", "scope": "widget_class", "max": 1},
            {"type": "forbidden_nesting", "outerIdentity": "Card", "innerIdentity": "Card"},
            {"type": "required_companion", "identity": "Input", "companionIdentity": "Label", "relation": "sibling"},
            {"type": "allowed_parents", "identity": "Row", "parents": ["Table"]},
            {"type": "variant_context", "identity": "Button/Primary", "variant": "Compact", "allowedScopes": ["widget_class"]},
            {"type": "forbidden_identity_in_scope", "identity": "Banner", "scope": "compilation_unit"},
        )
        for predicate in predicates:
            with self.subTest(predicate=predicate["type"]):
                rule = {**MACHINE_RULE, "predicate": predicate}
                self.assertEqual(list(validator.iter_errors(rule)), [])
        invalid = {**MACHINE_RULE, "outsideSystem": True}
        self.assertTrue(list(validator.iter_errors(invalid)))

    def test_report_schema_pins_preview_only_non_production_authority(self) -> None:
        schema = json.loads(
            (SCHEMAS / "rules-validation-report.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(schema["properties"]["authority"]["const"], "preview_only")
        self.assertFalse(schema["properties"]["localChangesPerformed"]["const"])
        self.assertFalse(schema["properties"]["productionReady"]["const"])

    def test_rule_schema_rejects_outside_v1_scope_and_relation_vocabulary(self) -> None:
        schema = json.loads((SCHEMAS / "rule.schema.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        invalid_scope = {
            **MACHINE_RULE,
            "predicate": {
                "type": "forbidden_identity_in_scope",
                "identity": "Banner",
                "scope": "screen",
            },
        }
        invalid_relation = {
            **MACHINE_RULE,
            "predicate": {
                "type": "required_companion",
                "identity": "Input",
                "companionIdentity": "Label",
                "relation": "ancestor",
            },
        }
        self.assertTrue(list(validator.iter_errors(invalid_scope)))
        self.assertTrue(list(validator.iter_errors(invalid_relation)))


class RuleFoundationContractTest(unittest.TestCase):
    def test_explicit_marker_parses_and_ordinary_prose_is_only_a_warning(self) -> None:
        from guardian_core.rules import parse_description_markers, validate_rules

        text = "Ordinary description.\n[dsg-rule id=button-primary.max-per-widget class=machine]\nmax_instances_per_scope: identity=Button/Primary scope=widget_class max=1\n[/dsg-rule]\nMore prose."
        candidates = parse_description_markers(
            text,
            host_kind="component",
            host_identity="Button/Primary",
            figma=FIGMA,
        )
        result = validate_rules(
            candidates,
            known_identities=frozenset({"Button/Primary"}),
            source_type="figma_description",
        )
        self.assertEqual(result["rules"], [MACHINE_RULE])
        self.assertEqual(result["report"]["status"], "allowed")
        self.assertEqual(result["report"]["summary"], {"ok": 1, "warnings": 1, "errors": 0, "notAssessed": 0})
        self.assertEqual(
            {item["reasonCode"] for item in result["report"]["entries"]},
            {"ok", "unmarked_text_ignored"},
        )

    def test_unknown_predicate_duplicate_id_and_unknown_field_fail_closed(self) -> None:
        from guardian_core.rules import validate_rules

        unknown_predicate = {
            **MACHINE_RULE,
            "ruleId": "rule.unknown-predicate",
            "predicate": {"type": "allow_everything", "identity": "Button/Primary"},
        }
        unknown_field = {**MACHINE_RULE, "ruleId": "rule.unknown-field", "closestBlue": True}
        result = validate_rules(
            [MACHINE_RULE, MACHINE_RULE, unknown_predicate, unknown_field],
            known_identities=frozenset({"Button/Primary"}),
            source_type="artifact",
        )
        self.assertEqual(result["report"]["status"], "invalid")
        reasons = {item["reasonCode"] for item in result["report"]["entries"]}
        self.assertTrue({"duplicate_rule_id", "unknown_predicate", "unknown_field"}.issubset(reasons))

    def test_missing_identity_coverage_is_not_assessed_and_unknown_identity_is_invalid(self) -> None:
        from guardian_core.rules import validate_rules

        unassessed = validate_rules(
            [MACHINE_RULE], known_identities=None, source_type="artifact"
        )["report"]
        self.assertEqual(unassessed["status"], "not_assessed")
        self.assertEqual(unassessed["identityCoverage"], "not_assessed")
        self.assertEqual(unassessed["summary"]["notAssessed"], 1)

        invalid = validate_rules(
            [MACHINE_RULE],
            known_identities=frozenset({"Button/Secondary"}),
            source_type="artifact",
        )["report"]
        self.assertEqual(invalid["status"], "invalid")
        self.assertIn("unknown_identity", {item["reasonCode"] for item in invalid["entries"]})

    def test_rule_digest_and_report_are_order_independent_and_do_not_disclose_statements(self) -> None:
        from guardian_core.rules import validate_rules

        informative = {
            "schemaVersion": 1,
            "ruleId": "copy.sentence-case",
            "class": "informative",
            "statement": "Sensitive local writing guidance.",
            "appliesTo": {"kind": "system"},
            "provenance": {"origin": "team_artifact", "figma": None, "docRef": "local-rules"},
        }
        one = validate_rules(
            [informative, MACHINE_RULE],
            known_identities=frozenset({"Button/Primary"}),
            source_type="artifact",
        )
        two = validate_rules(
            [MACHINE_RULE, informative],
            known_identities=frozenset({"Button/Primary"}),
            source_type="artifact",
        )
        self.assertEqual(one, two)
        rendered = json.dumps(one["report"], sort_keys=True)
        self.assertNotIn(informative["statement"], rendered)
        self.assertNotIn("local-rules", rendered)

    def test_artifact_loader_rejects_oversized_and_duplicate_key_inputs_without_echoing_content(self) -> None:
        from guardian_core.rules import RuleValidationError, load_rule_artifact

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "rules.json"
            duplicate.write_text('[{"schemaVersion":1,"schemaVersion":1}]', encoding="utf-8")
            with self.assertRaises(RuleValidationError) as duplicate_error:
                load_rule_artifact(duplicate)
            self.assertEqual(duplicate_error.exception.reason_code, "duplicate_json_key")
            self.assertNotIn(str(duplicate), str(duplicate_error.exception))

            oversized = root / "large.json"
            oversized.write_bytes(b"[" + b" " * (1024 * 1024 + 1) + b"]")
            with self.assertRaises(RuleValidationError) as size_error:
                load_rule_artifact(oversized)
            self.assertEqual(size_error.exception.reason_code, "input_too_large")
            self.assertNotIn(str(oversized), str(size_error.exception))


if __name__ == "__main__":
    unittest.main()
