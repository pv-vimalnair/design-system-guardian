from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
ADAPTER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.canonical import canonical_json_bytes, sha256_digest
from guardian_core.flutter_config import (
    _compile_usage_rules,
    _validate_config_document,
)
from guardian_core.flutter_adapter import normalize_flutter_adapter_result
from adapters.flutter.tools.guardian_flutter_contract import (
    validate_adapter_config as validate_portable_config,
)


DIGEST = "a" * 64
WIDGET = "package:example_company_design_system/design.dart#ApprovedCard"


def mapping(symbol: str) -> dict[str, object]:
    return {
        "framework": "flutter",
        "symbol": symbol,
        "approved": True,
        "inferred": False,
        "sourceDigest": DIGEST,
    }


def component(identity: str, *symbols: str) -> dict[str, object]:
    return {
        "kind": "component",
        "identity": identity,
        "status": "approved",
        "approved": True,
        "deprecated": False,
        "provenance": {"published": True},
        "figma": {"published": True},
        "codeMappings": [mapping(symbol) for symbol in symbols],
    }


def rule(
    rule_id: str,
    rule_class: str,
    *,
    predicate: dict[str, object] | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schemaVersion": 1,
        "ruleId": rule_id,
        "class": rule_class,
        "appliesTo": {"kind": "system"},
        "provenance": {
            "origin": "team_artifact",
            "figma": None,
            "docRef": "local://rules",
        },
    }
    if predicate is None:
        value["statement"] = "Local guidance."
    else:
        value["predicate"] = predicate
    return value


class FlutterUsageRuleContractTests(unittest.TestCase):
    def v2_config(
        self,
        *,
        source_cut: dict[str, object],
        coverage_status: str = "complete",
        inactive: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        config = json.loads(
            (ADAPTER_ROOT / "test/fixtures/config.valid.json").read_text()
        )
        inactive = [] if inactive is None else inactive
        config.update(
            {
                "schemaVersion": 2,
                "sourceCutDigest": sha256_digest(source_cut),
                "ruleSnapshotId": config["snapshotId"],
                "rulesDigest": "b" * 64,
                "activeUsageRules": [],
                "usageRuleCoverage": {
                    "status": coverage_status,
                    "activeRuleIds": [],
                    "inactive": inactive,
                    "informativeRuleIds": [],
                },
            }
        )
        config.pop("configDigest")
        config["configDigest"] = sha256_digest(config)
        return config

    def test_compiles_only_exact_activated_compilation_unit_predicates(self) -> None:
        snapshot = {
            "registry": {
                "components": [component("Card/Primary", WIDGET)],
                "icons": [],
            },
            "rules": [
                rule(
                    "a.forbidden",
                    "machine",
                    predicate={
                        "type": "forbidden_identity_in_scope",
                        "identity": "Card/Primary",
                        "scope": "compilation_unit",
                    },
                ),
                rule(
                    "b.maximum",
                    "machine",
                    predicate={
                        "type": "max_instances_per_scope",
                        "identity": "Card/Primary",
                        "scope": "compilation_unit",
                        "max": 2,
                    },
                ),
                rule(
                    "c.deferred",
                    "machine",
                    predicate={
                        "type": "max_instances_per_scope",
                        "identity": "Card/Primary",
                        "scope": "widget_class",
                        "max": 1,
                    },
                ),
                rule("d.judgment", "judgment"),
                rule("e.informative", "informative"),
            ],
            "activatedCapabilities": [
                {
                    "predicate": "forbidden_identity_in_scope",
                    "scope": "compilation_unit",
                },
                {
                    "predicate": "max_instances_per_scope",
                    "scope": "compilation_unit",
                },
            ],
        }

        active, coverage = _compile_usage_rules(snapshot, {WIDGET})

        self.assertEqual(
            active,
            [
                {
                    "ruleId": "a.forbidden",
                    "predicate": "forbidden_identity_in_scope",
                    "scope": "compilation_unit",
                    "constructorIdentities": [WIDGET],
                },
                {
                    "ruleId": "b.maximum",
                    "predicate": "max_instances_per_scope",
                    "scope": "compilation_unit",
                    "constructorIdentities": [WIDGET],
                    "max": 2,
                },
            ],
        )
        self.assertEqual(coverage["status"], "incomplete")
        self.assertEqual(coverage["activeRuleIds"], ["a.forbidden", "b.maximum"])
        self.assertEqual(
            coverage["inactive"],
            [
                {"ruleId": "c.deferred", "reasonCode": "unsupported_predicate_scope"},
                {"ruleId": "d.judgment", "reasonCode": "unsupported_rule_class"},
            ],
        )
        self.assertEqual(coverage["informativeRuleIds"], ["e.informative"])

    def test_unmapped_machine_identity_is_incomplete_and_never_guessed(self) -> None:
        snapshot = {
            "registry": {"components": [component("Card/Primary")], "icons": []},
            "rules": [
                rule(
                    "a.unmapped",
                    "machine",
                    predicate={
                        "type": "forbidden_identity_in_scope",
                        "identity": "Card/Primary",
                        "scope": "compilation_unit",
                    },
                )
            ],
            "activatedCapabilities": [
                {
                    "predicate": "forbidden_identity_in_scope",
                    "scope": "compilation_unit",
                },
                {
                    "predicate": "max_instances_per_scope",
                    "scope": "compilation_unit",
                },
            ],
        }
        active, coverage = _compile_usage_rules(snapshot, set())
        self.assertEqual(active, [])
        self.assertEqual(
            coverage["inactive"],
            [{"ruleId": "a.unmapped", "reasonCode": "identity_not_mapped"}],
        )
        self.assertEqual(coverage["status"], "incomplete")

    def test_v2_config_is_strict_and_v1_fixture_bytes_remain_unchanged(self) -> None:
        fixture_path = ADAPTER_ROOT / "test/fixtures/config.valid.json"
        before = fixture_path.read_bytes()
        v1 = json.loads(before)
        self.assertEqual(_validate_config_document(v1), v1)
        self.assertEqual(fixture_path.read_bytes(), before)

        v2 = copy.deepcopy(v1)
        v2.update(
            {
                "schemaVersion": 2,
                "ruleSnapshotId": v1["snapshotId"],
                "rulesDigest": "b" * 64,
                "activeUsageRules": [
                    {
                        "ruleId": "card.maximum",
                        "predicate": "max_instances_per_scope",
                        "scope": "compilation_unit",
                        "constructorIdentities": [v1["approvedIdentities"]["widgets"][0]],
                        "max": 1,
                    }
                ],
                "usageRuleCoverage": {
                    "status": "complete",
                    "activeRuleIds": ["card.maximum"],
                    "inactive": [],
                    "informativeRuleIds": [],
                },
            }
        )
        v2.pop("configDigest")
        v2["configDigest"] = sha256_digest(v2)
        self.assertEqual(_validate_config_document(v2), v2)
        self.assertEqual(validate_portable_config(v2), v2)

        outside = copy.deepcopy(v2)
        outside["activeUsageRules"][0]["constructorIdentities"] = [
            "package:other/design.dart#NearestCard"
        ]
        outside["configDigest"] = sha256_digest(
            {key: value for key, value in outside.items() if key != "configDigest"}
        )
        with self.assertRaisesRegex(ValueError, "approved widget"):
            _validate_config_document(outside)

    def test_v2_schema_and_dart_rule_are_present_without_replacing_v1(self) -> None:
        v1_path = ADAPTER_ROOT / "contracts/flutter-adapter-config.schema.json"
        v2_path = ADAPTER_ROOT / "contracts/flutter-adapter-config-v2.schema.json"
        self.assertEqual(json.loads(v1_path.read_text())["properties"]["schemaVersion"], {"const": 1})
        self.assertEqual(json.loads(v2_path.read_text())["properties"]["schemaVersion"], {"const": 2})
        rule_source = (ADAPTER_ROOT / "lib/src/rules/usage_rule.dart").read_text()
        self.assertIn("guardian_usage_rule", rule_source)
        self.assertIn("canonicalExpressionIdentity", rule_source)

    def test_usage_rule_counts_each_supported_resolved_invocation_node_once(self) -> None:
        rule_source = (
            ADAPTER_ROOT / "lib/src/rules/usage_rule.dart"
        ).read_text(encoding="utf-8")
        for invocation in (
            "visitInstanceCreationExpression",
            "visitMethodInvocation",
            "visitFunctionExpressionInvocation",
        ):
            with self.subTest(invocation=invocation):
                self.assertIn(invocation, rule_source)
        self.assertIn("canonicalExpressionIdentity(node)", rule_source)
        self.assertIn("HashSet<Expression>.identity()", rule_source)
        self.assertIn("if (!_seenNodes.add(node)) return;", rule_source)

        dart_test = (ADAPTER_ROOT / "test/usage_rule_test.dart").read_text(
            encoding="utf-8"
        )
        self.assertIn("UsageRuleInvocationFormsTest", dart_test)
        self.assertIn("ApprovedCard.make()", dart_test)
        self.assertIn("(ApprovedCard.make)()", dart_test)

    def test_incomplete_rule_coverage_stays_local_to_components_and_never_passes(self) -> None:
        source_cut = {
            "figmaFileVersions": {"library": "1"},
            "catalogDigest": "c" * 64,
            "codeConnectParseDigest": "d" * 64,
            "repositoryCommit": "e" * 40,
            "componentCatalogBuild": None,
        }
        config = self.v2_config(
            source_cut=source_cut,
            coverage_status="incomplete",
            inactive=[
                {
                    "ruleId": "card.judgment",
                    "reasonCode": "unsupported_rule_class",
                }
            ],
        )
        run_pin = {
            "schemaVersion": 1,
            "runId": "run-usage-rules",
            "profileId": config["profileId"],
            "snapshotId": config["snapshotId"],
            "policyDigest": config["policyDigest"],
            "sourceCut": source_cut,
        }
        coverage = {
            category: {
                "status": "not_assessed" if category == "components" else "allowed",
                "method": "dart_analyzer_ast",
                "diagnosticCount": 1 if category == "components" else 0,
            }
            for category in (
                "components",
                "icons",
                "colors",
                "typography",
                "spacing",
                "radii",
                "effects",
                "motion",
            )
        }
        result = {
            "schemaVersion": 1,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "status": "not_assessed",
            "binding": {
                "profileId": config["profileId"],
                "policyDigest": config["policyDigest"],
                "snapshotId": config["snapshotId"],
                "sourceCutDigest": config["sourceCutDigest"],
                "configDigest": config["configDigest"],
            },
            "analysis": {
                "method": "dart_analyzer_ast",
                "complete": True,
                "assessedFiles": 1,
                "totalFiles": 1,
            },
            "diagnostics": [
                {
                    "severity": "WARNING",
                    "code": "guardian_usage_rule",
                    "path": "lib/main.dart",
                    "line": 1,
                    "column": 1,
                    "length": 4,
                    "message": "usage rule violated",
                }
            ],
            "coverage": coverage,
            "suppressionScan": {
                "schemaVersion": 1,
                "method": "conservative_text_scan",
                "astProof": False,
                "findings": [],
            },
            "productionReady": False,
        }

        normalized = normalize_flutter_adapter_result(
            result,
            adapter_config=config,
            run_pin=run_pin,
        )
        self.assertEqual(normalized["categories"]["components"]["status"], "not_assessed")
        self.assertTrue(
            all(
                lane["status"] == "allowed"
                for category, lane in normalized["categories"].items()
                if category != "components"
            )
        )
        self.assertEqual(normalized["diagnostics"][0]["category"], "components")


if __name__ == "__main__":
    unittest.main()
