from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FlutterAdapterBypassGuardTests(unittest.TestCase):
    def read_rule(self, name: str) -> str:
        return (ROOT / "lib" / "src" / "rules" / name).read_text(encoding="utf-8")

    def test_governed_visual_types_reject_function_and_index_wrappers(self) -> None:
        for name in (
            "color_rule.dart",
            "text_style_rule.dart",
            "icon_rule.dart",
            "effect_rule.dart",
            "motion_rule.dart",
        ):
            with self.subTest(name=name):
                source = self.read_rule(name)
                self.assertIn("addMethodInvocation", source)
                self.assertIn("addFunctionExpressionInvocation", source)
                self.assertIn("addIndexExpression", source)
                self.assertIn("visitMethodInvocation", source)
                self.assertIn("visitFunctionExpressionInvocation", source)
                self.assertIn("visitIndexExpression", source)

    def test_raw_icon_data_construction_is_denied(self) -> None:
        source = self.read_rule("icon_rule.dart")
        self.assertIn("addInstanceCreationExpression", source)
        self.assertIn("visitInstanceCreationExpression", source)
        self.assertIn("expressionHasGovernedType(node, 'icons')", source)
        identity = (ROOT / "lib" / "src" / "config" / "canonical_element_identity.dart").read_text(
            encoding="utf-8"
        )
        self.assertIn("package:flutter/src/widgets/icon_data.dart#IconData", identity)

    def test_widget_returning_wrappers_require_an_exact_approved_mapping(self) -> None:
        source = self.read_rule("widget_rule.dart")
        self.assertIn("addMethodInvocation", source)
        self.assertIn("addFunctionExpressionInvocation", source)
        self.assertIn("addIndexExpression", source)
        self.assertIn("canonicalExpressionIdentity", source)
        self.assertIn("!config.isApproved('widgets', identity)", source)

    def test_canonical_identity_supports_resolved_invocations_only(self) -> None:
        source = (
            ROOT / "lib" / "src" / "config" / "canonical_element_identity.dart"
        ).read_text(encoding="utf-8")
        self.assertIn("MethodInvocation node", source)
        self.assertIn("node.methodName.element", source)
        self.assertIn("FunctionExpressionInvocation node", source)
        self.assertIn("node.element", source)
        self.assertNotIn("node.toSource()", source)


if __name__ == "__main__":
    unittest.main()
