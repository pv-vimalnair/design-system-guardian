from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FlutterVisualPrimitiveSemanticTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_visual_primitive_rule_is_default_on(self) -> None:
        rule_path = ROOT / "lib/src/rules/visual_primitive_rule.dart"
        self.assertTrue(rule_path.is_file(), "visual primitive rule is missing")
        plugin = self.read("lib/src/guardian_plugin.dart")
        self.assertIn("import 'rules/visual_primitive_rule.dart';", plugin)
        self.assertIn(
            "registry.registerWarningRule(GuardianVisualPrimitiveRule());",
            plugin,
        )
        self.assertEqual(plugin.count("registry.registerWarningRule("), 14)

    def test_rule_uses_resolved_ast_paths_for_invocations_types_and_mutation(self) -> None:
        source = self.read("lib/src/rules/visual_primitive_rule.dart")
        for registration in (
            "addInstanceCreationExpression",
            "addMethodInvocation",
            "addFunctionExpressionInvocation",
            "addClassDeclaration",
            "addNamedType",
            "addAssignmentExpression",
        ):
            self.assertIn(registration, source)
        for semantic_api in (
            "canonicalElementIdentity",
            "canonicalExpressionIdentity",
            "canonicalTypeHierarchyIdentities",
            "writeElement",
            "staticType",
            "visualDimensionArguments",
            "radiusArguments",
        ):
            self.assertIn(semantic_api, source)
        self.assertNotIn("toSource()", source)
        self.assertNotIn("RegExp", source)

    def test_exact_forbidden_type_identities_cover_required_primitive_families(self) -> None:
        source = self.read("lib/src/rules/visual_primitive_rule.dart")
        for identity in (
            "dart:ui#Paint",
            "dart:ui#Path",
            "dart:ui#Canvas",
            "dart:ui#PictureRecorder",
            "dart:ui#Shader",
            "dart:ui#Image",
            "dart:ui#Paragraph",
            "package:flutter/src/rendering/custom_paint.dart#CustomPainter",
            "package:flutter/src/painting/decoration.dart#Decoration",
            "package:flutter/src/painting/image_provider.dart#ImageProvider",
            "package:flutter/src/painting/image_resolution.dart#AssetImage",
            "package:flutter/src/painting/_network_image_io.dart#NetworkImage",
        ):
            self.assertIn(identity, source)

    def test_exact_raw_asset_and_drawing_entry_points_are_non_approvable(self) -> None:
        source = self.read("lib/src/rules/visual_primitive_rule.dart")
        for identity in (
            "package:flutter/src/widgets/image.dart#Image.asset",
            "package:flutter/src/widgets/image.dart#Image.network",
            "package:flutter/src/services/font_loader.dart#FontLoader",
            "package:flutter/src/services/asset_bundle.dart#AssetBundle.load",
            "package:flutter_svg/src/widget.dart#SvgPicture.asset",
            "dart:ui#Canvas.drawPath",
            "dart:ui#Canvas.clipPath",
            "dart:ui#Canvas.saveLayer",
        ):
            self.assertIn(identity, source)
        self.assertIn("_isForbiddenResolvedIdentity", source)
        self.assertIn("_isApprovedDesignSystemWrapper", source)
        self.assertLess(
            source.index("_isForbiddenResolvedIdentity(identity)"),
            source.index("_isApprovedDesignSystemWrapper(config, identity)"),
            "raw framework/community entry points must be denied before approval lookup",
        )

    def test_real_analyzer_testing_sources_cover_required_negative_cases(self) -> None:
        test_source = self.read("test/visual_primitive_rule_test.dart")
        self.assertIn("extends AnalysisRuleTest", test_source)
        self.assertIn("GuardianVisualPrimitiveRule", test_source)
        for case in (
            "paint.strokeWidth = 2",
            "Paint()..strokeWidth = 3",
            "options.width = 12",
            "options..radius = 8",
            "extends CustomPainter",
            "AssetImage('assets/raw.png')",
            "Image.asset('assets/raw.png')",
            "FontLoader('RawFont')",
            "canvas.drawPath",
            "canvas.clipPath",
            "canvas.saveLayer",
        ):
            self.assertIn(case, test_source)


if __name__ == "__main__":
    unittest.main()
