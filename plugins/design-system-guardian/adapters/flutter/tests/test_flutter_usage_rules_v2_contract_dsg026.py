from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, ValidationError


ADAPTER_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PLUGIN_ROOT))

from guardian_core.flutter_adapter import normalize_flutter_adapter_result
TOOL_PATH = ADAPTER_ROOT / "tools" / "guardian_flutter_contract.py"
EVALUATOR_DIGEST = (
    "24b38e5b0a7ffe35da9cb368613c693e42e95937d599922491aac2fced411846"
)
CATEGORIES = (
    "components",
    "icons",
    "colors",
    "typography",
    "spacing",
    "radii",
    "effects",
    "motion",
)


def canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "guardian_flutter_contract_v2",
        TOOL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Guardian Flutter contract tool")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FlutterUsageRulesV2ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def fixtures(self) -> tuple[dict, dict, dict]:
        source_cut = {
            "figmaFileVersions": {"library": "17"},
            "catalogDigest": "1" * 64,
            "codeConnectDigest": "2" * 64,
            "repositoryCommit": "3" * 40,
        }
        run_pin = {
            "schemaVersion": 1,
            "runId": "run-flutter-v2",
            "profileId": "example-company",
            "snapshotId": "4" * 64,
            "policyDigest": "5" * 64,
            "sourceState": "fresh",
            "sourceCut": source_cut,
        }
        card = "package:app/design.dart#ApprovedCard"
        companion = "package:app/design.dart#ApprovedCompanion"
        container = "package:app/design.dart#ApprovedContainer"
        variant = "package:app/design.dart#ApprovedCardVariant.compact"
        config = {
            "schemaVersion": 3,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "profileId": run_pin["profileId"],
            "policyDigest": run_pin["policyDigest"],
            "snapshotId": run_pin["snapshotId"],
            "sourceCutDigest": canonical_digest(source_cut),
            "toolchain": {
                "platformId": "windows-x64",
                "dartSdk": {
                    "contentDigest": "d" * 64,
                    "executableRelativePath": "bin/dart.exe",
                },
            },
            "requiredPackages": {
                "flutter": {
                    "contentDigest": "f" * 64,
                    "repositoryCommit": "3" * 40,
                }
            },
            "approvedPackages": {
                "app": {
                    "contentDigest": "6" * 64,
                    "repositoryCommit": "3" * 40,
                }
            },
            "approvedIdentities": {
                "colors": [],
                "textStyles": [],
                "icons": [],
                "dimensions": [],
                "effects": [],
                "motion": [],
                "widgets": [card, companion, container],
            },
            "componentVariants": {
                card: {"variant": [variant]},
            },
            "ruleSnapshotId": run_pin["snapshotId"],
            "rulesDigest": "7" * 64,
            "activeUsageRules": [
                {
                    "ruleId": "a.forbidden",
                    "predicate": "forbidden_identity_in_scope",
                    "scope": "compilation_unit",
                    "constructorIdentities": [card],
                },
                {
                    "ruleId": "b.maximum",
                    "predicate": "max_instances_per_scope",
                    "scope": "widget_class",
                    "constructorIdentities": [card],
                    "max": 1,
                },
                {
                    "ruleId": "c.nesting",
                    "predicate": "forbidden_nesting",
                    "outerConstructorIdentities": [container],
                    "innerConstructorIdentities": [card],
                },
                {
                    "ruleId": "d.companion",
                    "predicate": "required_companion",
                    "constructorIdentities": [card],
                    "companionConstructorIdentities": [companion],
                    "relation": "descendant",
                },
                {
                    "ruleId": "e.parents",
                    "predicate": "allowed_parents",
                    "constructorIdentities": [card],
                    "parentConstructorIdentities": [container],
                },
                {
                    "ruleId": "f.variant",
                    "predicate": "variant_context",
                    "constructorIdentities": [card],
                    "variantProperty": "variant",
                    "variantIdentities": [variant],
                    "allowedScopes": ["compilation_unit", "widget_class"],
                },
            ],
            "usageRuleCoverage": {
                "status": "complete",
                "activeRuleIds": [
                    "a.forbidden",
                    "b.maximum",
                    "c.nesting",
                    "d.companion",
                    "e.parents",
                    "f.variant",
                ],
                "inactive": [],
                "informativeRuleIds": ["z.guidance"],
            },
            "runId": run_pin["runId"],
            "evaluatorId": "guardian-flutter-usage-rules-v2",
            "evaluatorContractDigest": EVALUATOR_DIGEST,
            "authorizationDigest": "8" * 64,
        }
        config["configDigest"] = canonical_digest(config)
        result = {
            "schemaVersion": 2,
            "adapter": "flutter",
            "adapterVersion": "0.1.0",
            "status": "allowed",
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
            "diagnostics": [],
            "coverage": {
                category: {
                    "status": "allowed",
                    "method": "dart_analyzer_ast",
                    "diagnosticCount": 0,
                }
                for category in CATEGORIES
            },
            "suppressionScan": {
                "schemaVersion": 1,
                "method": "conservative_text_scan",
                "astProof": False,
                "findings": [],
            },
            "productionReady": True,
        }
        return config, run_pin, result

    def test_v3_config_and_v2_result_schema_are_strict_and_additive(self) -> None:
        config, run_pin, result = self.fixtures()
        self.assertEqual(self.tool.validate_adapter_config(config), config)

        config_schema = json.loads(
            (
                ADAPTER_ROOT
                / "contracts"
                / "flutter-adapter-config-v3.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(config_schema)
        validator.validate(config)
        wrong_contract = copy.deepcopy(config)
        wrong_contract["evaluatorContractDigest"] = "0" * 64
        with self.assertRaises(ValidationError):
            validator.validate(wrong_contract)

        schema_path = (
            ADAPTER_ROOT
            / "contracts"
            / "flutter-adapter-result-v2.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema['properties']['schemaVersion'], {'const': 2})

        normalized = self.tool.normalize_flutter_result_to_core(
            result,
            config,
            run_pin,
        )
        core_normalized = normalize_flutter_adapter_result(
            result,
            adapter_config=config,
            run_pin=run_pin,
        )
        self.assertEqual(core_normalized, normalized)
        usage = normalized["usageRulesEvidence"]
        self.assertEqual(usage["status"], "allowed")
        self.assertEqual(
            usage["assessedRuleIds"],
            config["usageRuleCoverage"]["activeRuleIds"],
        )
        self.assertEqual(usage["violatedRuleIds"], [])
        self.assertEqual(usage["notAssessed"], [])
        self.assertEqual(usage["informativeRuleIds"], ["z.guidance"])

    def test_conflict_wins_and_markers_are_not_inherited_diagnostics(self) -> None:
        config, run_pin, result = self.fixtures()
        result["schemaVersion"] = 2
        result["status"] = "not_assessed"
        result["productionReady"] = False
        result["coverage"]["components"]["status"] = "not_assessed"
        result["coverage"]["components"]["diagnosticCount"] = 1
        result["diagnostics"] = [
            {
                "severity": "WARNING",
                "code": "guardian_usage_rule",
                "path": "lib/main.dart",
                "line": 1,
                "column": 1,
                "length": 4,
                "message": (
                    "Design-system usage rule a.forbidden is violated "
                    "in this compilation unit."
                ),
            },
            {
                "severity": "WARNING",
                "code": "guardian_usage_rule_not_assessed",
                "path": "lib/main.dart",
                "line": 2,
                "column": 1,
                "length": 4,
                "message": (
                    "DSG_USAGE_RULE_NOT_ASSESSED_V1 "
                    "ruleId=b.maximum "
                    "reasonCode=incomplete_construction_graph"
                ),
            },
        ]

        normalized = self.tool.normalize_flutter_result_to_core(
            result,
            config,
            run_pin,
        )
        core_normalized = normalize_flutter_adapter_result(
            result,
            adapter_config=config,
            run_pin=run_pin,
        )
        self.assertEqual(core_normalized, normalized)
        usage = normalized["usageRulesEvidence"]
        self.assertEqual(usage["status"], "conflict")
        self.assertEqual(usage["violatedRuleIds"], ["a.forbidden"])
        self.assertEqual(
            usage["notAssessed"],
            [
                {
                    "ruleId": "b.maximum",
                    "reasonCode": "incomplete_construction_graph",
                }
            ],
        )
        self.assertEqual(len(normalized["diagnostics"]), 1)
        self.assertEqual(len(usage["diagnostics"]), 1)
        self.assertEqual(
            usage["diagnostics"][0]["inheritedDiagnosticId"],
            normalized["diagnostics"][0]["diagnosticId"],
        )

    def test_display_variant_and_caller_run_substitution_fail_closed(self) -> None:
        config, run_pin, result = self.fixtures()
        display_variant = copy.deepcopy(config)
        display_variant["activeUsageRules"][-1]["variantIdentities"] = ["Compact"]
        display_variant["configDigest"] = canonical_digest(
            {key: value for key, value in display_variant.items() if key != "configDigest"}
        )
        with self.assertRaises(self.tool.ContractError):
            self.tool.validate_adapter_config(display_variant)

        substituted = copy.deepcopy(config)
        substituted["runId"] = "another-run"
        substituted["configDigest"] = canonical_digest(
            {key: value for key, value in substituted.items() if key != "configDigest"}
        )
        result["binding"]["configDigest"] = substituted["configDigest"]
        with self.assertRaisesRegex(self.tool.ContractError, "runId"):
            self.tool.normalize_flutter_result_to_core(
                result,
                substituted,
                run_pin,
            )

    def test_result_v1_cannot_silently_drop_v3_usage_evidence(self) -> None:
        config, run_pin, result = self.fixtures()
        result["schemaVersion"] = 1
        with self.assertRaisesRegex(self.tool.ContractError, "result schema"):
            self.tool.normalize_flutter_result_to_core(
                result,
                config,
                run_pin,
            )


if __name__ == "__main__":
    unittest.main()
