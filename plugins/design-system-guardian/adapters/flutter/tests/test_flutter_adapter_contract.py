from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "guardian_flutter_contract.py"


def canonical_digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_tool():
    spec = importlib.util.spec_from_file_location("guardian_flutter_contract", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Guardian Flutter contract tool")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FlutterAdapterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = load_tool()

    def fixtures(self) -> tuple[dict, dict, dict]:
        source_cut = {
            "figmaFileVersions": {"file-A": "17"},
            "catalogDigest": "1" * 64,
            "codeConnectDigest": "2" * 64,
            "repositoryCommit": "3" * 40,
        }
        run_pin = {
            "schemaVersion": 1,
            "runId": "run-flutter-contract",
            "profileId": "example-company",
            "snapshotId": "4" * 64,
            "policyDigest": "5" * 64,
            "sourceState": "fresh",
            "sourceCut": source_cut,
        }
        config = {
            "schemaVersion": 1,
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
                "colors": ["package:app/design.dart#AppColors.primary"],
                "textStyles": ["package:app/design.dart#AppTypography.body"],
                "icons": ["package:app/design.dart#AppIcons.add"],
                "dimensions": ["package:app/design.dart#AppSpacing.medium"],
                "effects": ["package:app/design.dart#AppEffects.card"],
                "motion": ["package:app/design.dart#AppMotion.standard"],
                "widgets": ["package:app/design.dart#ApprovedCard"],
            },
            "componentVariants": {
                "package:app/design.dart#ApprovedCard": {
                    "variant": ["package:app/design.dart#ApprovedCardVariant.primary"]
                }
            },
        }
        config["configDigest"] = canonical_digest(config)
        coverage = {
            category: {
                "status": "allowed",
                "method": "dart_analyzer_ast",
                "diagnosticCount": 0,
            }
            for category in self.tool.AUDIT_CATEGORIES
        }
        result = {
            "schemaVersion": 1,
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
            "coverage": coverage,
            "suppressionScan": {
                "schemaVersion": 1,
                "method": "conservative_text_scan",
                "astProof": False,
                "findings": [],
            },
            "productionReady": True,
        }
        return config, run_pin, result

    def test_normalizer_projects_exact_core_audit_evidence(self) -> None:
        config, run_pin, result = self.fixtures()
        evidence = self.tool.normalize_flutter_result_to_core(result, config, run_pin)
        self.assertEqual(
            set(evidence),
            {
                "schemaVersion",
                "adapter",
                "supported",
                "configDigest",
                "sourceCut",
                "assessedFiles",
                "totalFiles",
                "categories",
                "diagnostics",
            },
        )
        self.assertEqual(evidence["sourceCut"], run_pin["sourceCut"])
        self.assertEqual(evidence["configDigest"], config["configDigest"])
        self.assertTrue(evidence["supported"])
        self.assertEqual(evidence["assessedFiles"], 1)
        self.assertEqual(evidence["totalFiles"], 1)
        self.assertEqual(evidence["diagnostics"], [])
        for category in self.tool.AUDIT_CATEGORIES:
            self.assertEqual(
                evidence["categories"][category],
                {"status": "allowed", "assessedItems": 1, "totalItems": 1},
            )
        fixture = json.loads(
            (ROOT / "test/fixtures/config.valid.json").read_text(encoding="utf-8")
        )
        validated = self.tool.validate_adapter_config(fixture)
        self.assertEqual(
            validated["configDigest"],
            "4d25041264e9ccba7cdd99d273bf9c9ab04d15c5659efde804d04cac4c157b6a",
        )

    def test_binding_mismatch_and_unknown_fields_fail_closed(self) -> None:
        config, run_pin, result = self.fixtures()
        mismatched = copy.deepcopy(result)
        mismatched["binding"]["profileId"] = "another-company"
        with self.assertRaisesRegex(self.tool.ContractError, "profileId"):
            self.tool.normalize_flutter_result_to_core(mismatched, config, run_pin)

        extra = copy.deepcopy(result)
        extra["inventedFallback"] = True
        with self.assertRaisesRegex(self.tool.ContractError, "unknown or missing"):
            self.tool.normalize_flutter_result_to_core(extra, config, run_pin)

    def test_each_analyzer_rule_maps_to_one_exact_audit_category(self) -> None:
        expected = {
            "guardian_unapproved_widget": "components",
            "guardian_unapproved_visual_primitive": "components",
            "guardian_unapproved_component_variant": "components",
            "guardian_unapproved_icon": "icons",
            "guardian_unapproved_color": "colors",
            "guardian_unapproved_text_style": "typography",
            "guardian_unapproved_dimension": "spacing",
            "guardian_unapproved_radius": "radii",
            "guardian_unapproved_effect": "effects",
            "guardian_unapproved_motion": "motion",
        }
        config, run_pin, baseline = self.fixtures()
        for code, category in expected.items():
            with self.subTest(code=code):
                result = copy.deepcopy(baseline)
                result["status"] = "allowed"
                result["productionReady"] = False
                result["diagnostics"] = [
                    {
                        "severity": "WARNING",
                        "code": code,
                        "path": "lib/example.dart",
                        "line": 8,
                        "column": 12,
                        "length": 4,
                        "message": "exact identity required",
                    }
                ]
                result["coverage"][category]["diagnosticCount"] = 1
                evidence = self.tool.normalize_flutter_result_to_core(result, config, run_pin)
                self.assertEqual(len(evidence["diagnostics"]), 1)
                self.assertEqual(evidence["diagnostics"][0]["category"], category)
                self.assertEqual(evidence["diagnostics"][0]["kind"], "violation")

    def test_unknown_guardian_diagnostic_and_config_digest_tampering_are_rejected(self) -> None:
        config, run_pin, result = self.fixtures()
        result["status"] = "allowed"
        result["productionReady"] = False
        result["diagnostics"] = [
            {
                "severity": "WARNING",
                "code": "guardian_use_closest_blue",
                "path": "lib/example.dart",
                "line": 1,
                "column": 1,
                "length": 1,
                "message": "unknown fallback",
            }
        ]
        with self.assertRaisesRegex(self.tool.ContractError, "unknown Guardian diagnostic"):
            self.tool.normalize_flutter_result_to_core(result, config, run_pin)

        config["approvedIdentities"]["colors"].append(
            "package:app/design.dart#OutsideNearestBlue"
        )
        clean_result = self.fixtures()[2]
        with self.assertRaisesRegex(self.tool.ContractError, "configDigest"):
            self.tool.normalize_flutter_result_to_core(clean_result, config, run_pin)

    def test_suppression_findings_become_deterministic_violations_not_ast_proof(self) -> None:
        config, run_pin, result = self.fixtures()
        result["status"] = "allowed"
        result["productionReady"] = False
        result["suppressionScan"]["findings"] = [
            {
                "path": "lib/example.dart",
                "line": 3,
                "text": "// ignore: design_system_guardian_flutter/guardian_unapproved_icon",
                "kind": "source_ignore",
            }
        ]
        evidence = self.tool.normalize_flutter_result_to_core(result, config, run_pin)
        self.assertEqual(len(evidence["diagnostics"]), 1)
        diagnostic = evidence["diagnostics"][0]
        self.assertEqual(diagnostic["category"], "icons")
        self.assertEqual(diagnostic["evidence"]["proofMethod"], "conservative_text_scan")
        self.assertFalse(diagnostic["evidence"]["astProof"])

    def test_incomplete_and_zero_file_analysis_never_project_green_coverage(self) -> None:
        config, run_pin, incomplete = self.fixtures()
        incomplete["status"] = "not_assessed"
        incomplete["productionReady"] = False
        incomplete["analysis"] = {
            "method": "dart_analyzer_ast",
            "complete": False,
            "assessedFiles": 1,
            "totalFiles": 2,
        }
        for lane in incomplete["coverage"].values():
            lane["status"] = "not_assessed"
        evidence = self.tool.normalize_flutter_result_to_core(incomplete, config, run_pin)
        self.assertFalse(any(
            lane["status"] == "allowed" for lane in evidence["categories"].values()
        ))
        self.assertEqual(evidence["assessedFiles"], 1)
        self.assertEqual(evidence["totalFiles"], 2)

        zero = self.fixtures()[2]
        zero["status"] = "not_assessed"
        zero["productionReady"] = False
        zero["analysis"] = {
            "method": "dart_analyzer_ast", "complete": True,
            "assessedFiles": 0, "totalFiles": 0,
        }
        with self.assertRaisesRegex(self.tool.ContractError, "at least one"):
            self.tool.normalize_flutter_result_to_core(zero, config, run_pin)


if __name__ == "__main__":
    unittest.main()
