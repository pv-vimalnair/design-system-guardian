from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from guardian_core.canonical import sha256_digest
from guardian_core.evaluator_upgrade import EVALUATOR_CONTRACT_DIGEST
from guardian_core.flutter_config import (
    _compile_usage_rules_v2,
    _validate_config_document,
)
from guardian_core.flutter_toolchain import current_platform_id, expected_dart_executable


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_ROOT = PLUGIN_ROOT / "adapters" / "flutter"
DIGEST = "a" * 64
LIBRARY = "package:example_company_design_system/design.dart"
CARD = f"{LIBRARY}#ApprovedCard"
INPUT = f"{LIBRARY}#ApprovedInput"
LABEL = f"{LIBRARY}#ApprovedLabel"
ROW = f"{LIBRARY}#ApprovedRow"
TABLE = f"{LIBRARY}#ApprovedTable"
BUTTON = f"{LIBRARY}#ApprovedButton"
BUTTON_VARIANT = f"{LIBRARY}#ApprovedButtonVariant.compact"


def mapping(symbol: str) -> dict[str, object]:
    return {
        "framework": "flutter",
        "symbol": symbol,
        "approved": True,
        "inferred": False,
        "sourceDigest": DIGEST,
    }


def component(identity: str, symbol: str, *, variants: list[str] | None = None) -> dict[str, object]:
    return {
        "kind": "component",
        "identity": identity,
        "status": "approved",
        "approved": True,
        "deprecated": False,
        "provenance": {"published": True},
        "figma": {"published": True},
        "codeMappings": [mapping(symbol)],
        "variants": [] if variants is None else variants,
        "properties": {},
    }


def machine(rule_id: str, predicate: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": "machine",
        "predicate": predicate,
        "appliesTo": {"kind": "system"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "local://rules",
        },
    }


def statement_rule(rule_id: str, rule_class: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": rule_class,
        "statement": "Local guidance.",
        "appliesTo": {"kind": "system"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "local://rules",
        },
    }


def snapshot_with_all_predicates() -> dict[str, object]:
    return {
        "registry": {
            "components": [
                component("Card", CARD),
                component("Input", INPUT),
                component("Label", LABEL),
                component("Row", ROW),
                component("Table", TABLE),
                component("Button", BUTTON, variants=[BUTTON_VARIANT]),
            ],
            "icons": [],
        },
        "rules": [
            machine(
                "a.forbidden",
                {
                    "type": "forbidden_identity_in_scope",
                    "identity": "Card",
                    "scope": "widget_class",
                },
            ),
            machine(
                "b.maximum",
                {
                    "type": "max_instances_per_scope",
                    "identity": "Card",
                    "scope": "compilation_unit",
                    "max": 2,
                },
            ),
            machine(
                "c.nesting",
                {
                    "type": "forbidden_nesting",
                    "outerIdentity": "Card",
                    "innerIdentity": "Input",
                },
            ),
            machine(
                "d.companion",
                {
                    "type": "required_companion",
                    "identity": "Input",
                    "companionIdentity": "Label",
                    "relation": "sibling",
                },
            ),
            machine(
                "e.parents",
                {
                    "type": "allowed_parents",
                    "identity": "Row",
                    "parents": ["Table"],
                },
            ),
            machine(
                "f.variant",
                {
                    "type": "variant_context",
                    "identity": "Button",
                    "variant": BUTTON_VARIANT,
                    "allowedScopes": ["compilation_unit", "widget_class"],
                },
            ),
            statement_rule("g.judgment", "judgment"),
            statement_rule("h.informative", "informative"),
        ],
    }


class FlutterConfigV3Test(unittest.TestCase):
    def test_compiles_all_six_predicates_with_only_exact_analyzer_identities(self) -> None:
        snapshot = snapshot_with_all_predicates()
        active, coverage = _compile_usage_rules_v2(
            snapshot,
            {CARD, INPUT, LABEL, ROW, TABLE, BUTTON},
            {BUTTON: {"variant": [BUTTON_VARIANT]}},
        )

        self.assertEqual(
            active,
            [
                {
                    "ruleId": "a.forbidden",
                    "predicate": "forbidden_identity_in_scope",
                    "scope": "widget_class",
                    "constructorIdentities": [CARD],
                },
                {
                    "ruleId": "b.maximum",
                    "predicate": "max_instances_per_scope",
                    "scope": "compilation_unit",
                    "constructorIdentities": [CARD],
                    "max": 2,
                },
                {
                    "ruleId": "c.nesting",
                    "predicate": "forbidden_nesting",
                    "outerConstructorIdentities": [CARD],
                    "innerConstructorIdentities": [INPUT],
                },
                {
                    "ruleId": "d.companion",
                    "predicate": "required_companion",
                    "constructorIdentities": [INPUT],
                    "companionConstructorIdentities": [LABEL],
                    "relation": "sibling",
                },
                {
                    "ruleId": "e.parents",
                    "predicate": "allowed_parents",
                    "constructorIdentities": [ROW],
                    "parentConstructorIdentities": [TABLE],
                },
                {
                    "ruleId": "f.variant",
                    "predicate": "variant_context",
                    "constructorIdentities": [BUTTON],
                    "variantProperty": "variant",
                    "variantIdentities": [BUTTON_VARIANT],
                    "allowedScopes": ["compilation_unit", "widget_class"],
                },
            ],
        )
        self.assertEqual(
            coverage,
            {
                "status": "incomplete",
                "activeRuleIds": [
                    "a.forbidden",
                    "b.maximum",
                    "c.nesting",
                    "d.companion",
                    "e.parents",
                    "f.variant",
                ],
                "inactive": [
                    {
                        "ruleId": "g.judgment",
                        "reasonCode": "unsupported_rule_class",
                    }
                ],
                "informativeRuleIds": ["h.informative"],
            },
        )

    def test_unmapped_or_similar_identity_and_variant_never_become_active(self) -> None:
        snapshot = snapshot_with_all_predicates()
        snapshot["rules"] = [
            machine(
                "a.identity",
                {
                    "type": "allowed_parents",
                    "identity": "RowCopy",
                    "parents": ["Table"],
                },
            ),
            machine(
                "b.variant",
                {
                    "type": "variant_context",
                    "identity": "Button",
                    "variant": f"{LIBRARY}#ApprovedButtonVariant.compactCopy",
                    "allowedScopes": ["widget_class"],
                },
            ),
        ]

        active, coverage = _compile_usage_rules_v2(
            snapshot,
            {CARD, INPUT, LABEL, ROW, TABLE, BUTTON},
            {BUTTON: {"variant": [BUTTON_VARIANT]}},
        )

        self.assertEqual(active, [])
        self.assertEqual(
            coverage["inactive"],
            [
                {"ruleId": "a.identity", "reasonCode": "identity_not_mapped"},
                {"ruleId": "b.variant", "reasonCode": "variant_not_mapped"},
            ],
        )

    def test_malformed_predicate_is_rejected_instead_of_deferred(self) -> None:
        snapshot = snapshot_with_all_predicates()
        snapshot["rules"] = [
            machine(
                "a.maximum",
                {
                    "type": "max_instances_per_scope",
                    "identity": "Card",
                    "scope": "widget_class",
                    "max": True,
                },
            )
        ]
        with self.assertRaisesRegex(ValueError, "maximum"):
            _compile_usage_rules_v2(
                snapshot,
                {CARD, INPUT, LABEL, ROW, TABLE, BUTTON},
                {BUTTON: {"variant": [BUTTON_VARIANT]}},
            )

    def test_config_v3_requires_exact_evaluator_and_authorization_bindings(self) -> None:
        fixture = json.loads(
            (ADAPTER_ROOT / "test" / "fixtures" / "config.valid.json").read_text(
                encoding="utf-8"
            )
        )
        platform_id = current_platform_id()
        fixture["toolchain"] = {
            "platformId": platform_id,
            "dartSdk": {
                "contentDigest": "d" * 64,
                "executableRelativePath": expected_dart_executable(platform_id),
            },
        }
        fixture.update(
            {
                "schemaVersion": 3,
                "runId": "run-rules-v2",
                "ruleSnapshotId": fixture["snapshotId"],
                "rulesDigest": "b" * 64,
                "evaluatorId": "guardian-flutter-usage-rules-v2",
                "evaluatorContractDigest": EVALUATOR_CONTRACT_DIGEST,
                "authorizationDigest": "d" * 64,
                "activeUsageRules": [],
                "usageRuleCoverage": {
                    "status": "complete",
                    "activeRuleIds": [],
                    "inactive": [],
                    "informativeRuleIds": [],
                },
            }
        )
        fixture.pop("configDigest")
        fixture["configDigest"] = sha256_digest(fixture)

        self.assertEqual(_validate_config_document(fixture), fixture)
        invalid_values = {
            "runId": " caller-substitution",
            "evaluatorId": "caller-substitution",
            "evaluatorContractDigest": "caller-substitution",
            "authorizationDigest": "caller-substitution",
        }
        for field, invalid_value in invalid_values.items():
            with self.subTest(field=field):
                tampered = copy.deepcopy(fixture)
                tampered[field] = invalid_value
                tampered["configDigest"] = sha256_digest(
                    {key: value for key, value in tampered.items() if key != "configDigest"}
                )
                with self.assertRaises(ValueError):
                    _validate_config_document(tampered)

    def test_v3_schema_is_additive_and_v1_v2_contracts_remain_present(self) -> None:
        versions = {
            1: ADAPTER_ROOT / "contracts" / "flutter-adapter-config.schema.json",
            2: ADAPTER_ROOT / "contracts" / "flutter-adapter-config-v2.schema.json",
            3: ADAPTER_ROOT / "contracts" / "flutter-adapter-config-v3.schema.json",
        }
        self.assertEqual(
            {
                version: json.loads(path.read_text(encoding="utf-8"))["properties"][
                    "schemaVersion"
                ]
                for version, path in versions.items()
            },
            {1: {"const": 1}, 2: {"const": 2}, 3: {"const": 3}},
        )


if __name__ == "__main__":
    unittest.main()
