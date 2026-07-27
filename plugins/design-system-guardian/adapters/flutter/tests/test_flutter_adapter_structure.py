from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FlutterAdapterStructureTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_pubspec_pins_supported_analyzer_plugin_stack(self) -> None:
        pubspec = self.read("pubspec.yaml")
        self.assertIn("name: design_system_guardian_flutter", pubspec)
        self.assertIn("sdk: '>=3.12.0 <4.0.0'", pubspec)
        self.assertIn("flutter: '>=3.44.0'", pubspec)
        self.assertIn("analysis_server_plugin: 0.3.15", pubspec)
        self.assertIn("analyzer: 13.0.0", pubspec)
        self.assertIn("analyzer_plugin: 0.14.9", pubspec)
        self.assertIn("analyzer_testing: 0.2.6", pubspec)
        self.assertIn("test: 1.31.2", pubspec)
        self.assertNotIn("custom_lint", pubspec)

    def test_entrypoint_uses_new_supported_plugin_and_default_on_warnings(self) -> None:
        main = self.read("lib/main.dart")
        plugin = self.read("lib/src/guardian_plugin.dart")
        self.assertIn("final plugin = DesignSystemGuardianFlutterPlugin();", main)
        self.assertIn("extends Plugin", plugin)
        self.assertIn("void register(PluginRegistry registry)", plugin)
        self.assertEqual(plugin.count("registry.registerWarningRule("), 14)
        self.assertNotIn("registerLintRule", plugin)
        self.assertNotIn("ServerPlugin", main + plugin)

    def test_each_required_rule_uses_analysis_rule_and_ast_visitor(self) -> None:
        required = {
            "config_binding_rule.dart": "addCompilationUnit",
            "color_rule.dart": "addInstanceCreationExpression",
            "text_style_rule.dart": "addInstanceCreationExpression",
            "icon_rule.dart": "addPrefixedIdentifier",
            "dimension_rule.dart": "addNamedArgument",
            "effect_rule.dart": "addInstanceCreationExpression",
            "motion_rule.dart": "addInstanceCreationExpression",
            "radius_rule.dart": "addNamedArgument",
            "sentinel_presence_rule.dart": "addInstanceCreationExpression",
            "widget_rule.dart": "addInstanceCreationExpression",
            "variant_rule.dart": "addInstanceCreationExpression",
            "visual_primitive_rule.dart": "addAssignmentExpression",
            "suppression_rule.dart": "addCompilationUnit",
        }
        for filename, registration in required.items():
            with self.subTest(filename=filename):
                source = self.read(f"lib/src/rules/{filename}")
                self.assertIn("extends AnalysisRule", source)
                self.assertIn("extends SimpleAstVisitor<void>", source)
                self.assertIn("void registerNodeProcessors(", source)
                self.assertIn(registration, source)
                self.assertIn("static const LintCode code", source)
                self.assertIn("reportAt", source)

    def test_rules_cover_all_guardian_categories_and_exact_identity_checks(self) -> None:
        rules = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "lib/src/rules").glob("*.dart"))
        )
        for category in (
            "colors",
            "textStyles",
            "icons",
            "dimensions",
            "effects",
            "motion",
            "widgets",
            "componentVariants",
        ):
            self.assertIn(category, rules)
        self.assertIn("canonicalElementIdentity", rules)
        self.assertIn("isApproved", rules)
        self.assertIn("IntegerLiteral", rules)
        self.assertIn("DoubleLiteral", rules)
        self.assertIn("frameworkDefault", rules)

    def test_config_contract_is_digest_verified_and_bound_to_pinned_run(self) -> None:
        loader = self.read("lib/src/config/adapter_config.dart")
        schema = json.loads(self.read("contracts/flutter-adapter-config.schema.json"))
        required = set(schema["required"])
        self.assertTrue(
            {
                "profileId",
                "policyDigest",
                "snapshotId",
                "sourceCutDigest",
                "configDigest",
                "approvedPackages",
                "approvedIdentities",
                "componentVariants",
            }.issubset(required)
        )
        self.assertIn(".design-system-guardian", loader)
        self.assertIn("flutter-adapter.json", loader)
        self.assertIn("context.package?.root.path", loader)
        self.assertIn("verifyConfigDigest", loader)
        self.assertIn("ConfigBinding.invalid", loader)
        self.assertIn("ConfigBinding.unbound", loader)
        for binding in ("profileId", "policyDigest", "snapshotId", "sourceCutDigest"):
            self.assertIn(binding, loader)

    def test_semantic_identities_use_resolved_elements_not_name_guessing(self) -> None:
        identity = self.read("lib/src/config/canonical_element_identity.dart")
        self.assertIn("Element? element", identity)
        self.assertIn("element.library", identity)
        self.assertIn("firstFragment.source.uri", identity)
        self.assertNotIn("RegExp", identity)
        self.assertNotIn("toSource()", identity)

    def test_deterministic_result_contract_separates_ast_and_text_scan_evidence(self) -> None:
        schema = json.loads(self.read("contracts/flutter-adapter-result.schema.json"))
        self.assertEqual(schema["properties"]["adapter"]["const"], "flutter")
        self.assertEqual(schema["properties"]["schemaVersion"]["const"], 1)
        required = set(schema["required"])
        self.assertTrue(
            {"binding", "diagnostics", "coverage", "suppressionScan", "productionReady"}.issubset(
                required
            )
        )
        coverage_categories = set(schema["properties"]["coverage"]["required"])
        self.assertEqual(
            coverage_categories,
            {
                "components",
                "icons",
                "colors",
                "typography",
                "spacing",
                "radii",
                "effects",
                "motion",
            },
        )
        tool = self.read("tools/guardian_flutter_contract.py")
        self.assertIn('"method": "dart_analyzer_ast"', tool)
        self.assertIn('"method": "conservative_text_scan"', tool)
        self.assertIn('"astProof": False', tool)
        self.assertIn("sorted(", tool)

    def test_external_suppression_scan_is_conservative_and_deterministic(self) -> None:
        tool = ROOT / "tools/guardian_flutter_contract.py"
        fixture = ROOT / "test/fixtures/violations.dart"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "suppression.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(tool),
                    "scan-suppressions",
                    "--project",
                    str(fixture.parent),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["method"], "conservative_text_scan")
            self.assertFalse(payload["astProof"])
            self.assertGreaterEqual(len(payload["findings"]), 1)
            self.assertEqual(
                payload["findings"],
                sorted(payload["findings"], key=lambda item: (item["path"], item["line"], item["text"])),
            )

    def test_sentinel_manifest_and_dart_widget_are_fixed_and_non_promotable(self) -> None:
        manifest_path = ROOT / "assets/sentinels/manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        self.assertEqual(len(manifest_bytes), 630)
        self.assertNotIn(b"\r", manifest_bytes)
        self.assertTrue(manifest_bytes.endswith(b"\n"))
        self.assertFalse(manifest_bytes.endswith(b"\n\n"))
        manifest = json.loads(manifest_bytes)
        expected_digest = "102743bb7512a31cfcffef46885c4b34076b9a0575a0711e0a0f1127cb105f79"
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        declared_digest = self.read("assets/sentinels/manifest.sha256").strip()
        dart = self.read("lib/src/sentinels/guardian_missing_sentinel.dart")
        self.assertEqual(digest, expected_digest)
        self.assertEqual(declared_digest, expected_digest)
        self.assertIn(expected_digest, dart)
        self.assertEqual(manifest["namespace"], "design_system_guardian.sentinel.v1")
        self.assertFalse(manifest["productionReady"])
        self.assertFalse(manifest["automaticPromotion"])
        self.assertEqual(manifest["style"]["background"], "#FF00FF")
        self.assertEqual(manifest["style"]["border"], "#00FFFF")
        self.assertEqual(manifest["style"]["foreground"], "#000000")
        for label in (
            "MISSING ICON",
            "MISSING COLOR",
            "MISSING TEXT STYLE",
            "MISSING COMPONENT",
            "MISSING TOKEN",
        ):
            self.assertIn(label, dart)
        self.assertIn("requestId", dart)
        self.assertIn("policyDigest", dart)
        self.assertIn("productionReady = false", dart)

    def test_fixtures_cover_approved_violating_and_unbound_cases(self) -> None:
        approved = self.read("test/fixtures/approved.dart")
        violations = self.read("test/fixtures/violations.dart")
        unbound = json.loads(self.read("test/fixtures/config.unbound.json"))
        for snippet in (
            "Color(0x",
            "TextStyle(",
            "Icons.add",
            "width: 12",
            "BoxShadow(",
            "ignore: design_system_guardian_flutter/",
        ):
            self.assertIn(snippet, violations)
        for symbol in (
            "AppColors.primary",
            "AppTypography.body",
            "AppIcons.add",
            "AppSpacing.medium",
            "AppEffects.card",
            "ApprovedCard",
            "ApprovedCardVariant.primary",
        ):
            self.assertIn(symbol, approved)
        self.assertNotIn("snapshotId", unbound)

    def test_readme_contains_explicit_optional_commands_and_runtime_disclaimer(self) -> None:
        readme = self.read("README.md")
        for command in (
            "flutter pub get",
            "dart analyze --format machine",
            "flutter test",
            "guardian_flutter_contract.py scan-suppressions",
            "guardian_flutter_contract.py normalize",
        ):
            self.assertIn(command, readme)
        self.assertIn("flutter 3.44+/dart 3.12+", readme.lower())
        self.assertIn("windows and ubuntu", readme.lower())
        self.assertIn("regex is not ast proof", readme.lower())


if __name__ == "__main__":
    unittest.main()
