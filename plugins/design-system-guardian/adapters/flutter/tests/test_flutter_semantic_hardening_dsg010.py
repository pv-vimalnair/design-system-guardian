from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FlutterSemanticHardeningTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_attestation_rule_is_default_on_and_config_digest_bound(self) -> None:
        plugin = self.read("lib/src/guardian_plugin.dart")
        rule = self.read("lib/src/rules/compilation_unit_attestation_rule.dart")
        self.assertIn("GuardianCompilationUnitAttestationRule", plugin)
        self.assertEqual(plugin.count("registry.registerWarningRule("), 14)
        self.assertIn("addCompilationUnit", rule)
        self.assertIn("guardian_compilation_unit_attestation", rule)
        self.assertIn("binding.config!.configDigest", rule)
        self.assertIn("DSG_ATTESTATION_V1 configDigest={0}", rule)

    def test_type_checks_use_exact_resolved_hierarchy_not_short_names(self) -> None:
        identity = self.read("lib/src/config/canonical_element_identity.dart")
        self.assertIn("canonicalTypeHierarchyIdentities", identity)
        self.assertIn("type.element", identity)
        self.assertIn("type.allSupertypes", identity)
        self.assertIn("governedTypeIdentities", identity)
        for rule in ("color_rule.dart", "text_style_rule.dart", "icon_rule.dart", "effect_rule.dart", "motion_rule.dart", "widget_rule.dart"):
            with self.subTest(rule=rule):
                source = self.read(f"lib/src/rules/{rule}")
                self.assertIn("expressionHasGovernedType", source)
                self.assertNotIn("expressionTypeName", source)

    def test_effects_and_motion_cover_required_exact_type_families(self) -> None:
        identity = self.read("lib/src/config/canonical_element_identity.dart")
        for exact in (
            "dart:ui#ColorFilter",
            "package:flutter/src/painting/decoration.dart#Decoration",
            "package:flutter/src/painting/gradient.dart#Gradient",
            "package:flutter/src/painting/box_border.dart#BoxBorder",
            "package:flutter/src/painting/borders.dart#ShapeBorder",
            "package:flutter/src/animation/animations.dart#CurvedAnimation",
            "package:flutter/src/animation/curves.dart#Cubic",
            "package:flutter/src/animation/tween.dart#ColorTween",
        ):
            self.assertIn(exact, identity)

    def test_widgets_and_variants_cover_static_method_and_function_expressions(self) -> None:
        widget = self.read("lib/src/rules/widget_rule.dart")
        for registration in ("addPrefixedIdentifier", "addPropertyAccess", "addSimpleIdentifier"):
            self.assertIn(registration, widget)
        variants = self.read("lib/src/rules/variant_rule.dart")
        for registration in ("addMethodInvocation", "addFunctionExpressionInvocation"):
            self.assertIn(registration, variants)
        self.assertIn("_checkInvocation", variants)
        self.assertIn("canonicalExpressionIdentity", variants)

    def test_dimensions_and_radii_cover_resolved_positional_arguments(self) -> None:
        support = self.read("lib/src/rules/rule_support.dart")
        self.assertIn("resolvedExecutable", support)
        self.assertIn("formalParameters", support)
        self.assertIn("governedArguments", support)
        for rule in ("dimension_rule.dart", "radius_rule.dart"):
            source = self.read(f"lib/src/rules/{rule}")
            self.assertIn("addInstanceCreationExpression", source)
            self.assertIn("addMethodInvocation", source)
            self.assertIn("addFunctionExpressionInvocation", source)
            self.assertIn("governedArguments", source)
            self.assertIn("canonicalExpressionIdentity", source)

    def test_sentinel_rule_requires_host_evidence_and_exact_literal_arguments(self) -> None:
        loader = self.read("lib/src/sentinels/sentinel_evidence.dart")
        rule = self.read("lib/src/rules/sentinel_presence_rule.dart")
        self.assertIn("DESIGN_SYSTEM_GUARDIAN_SENTINEL_EVIDENCE", loader)
        self.assertIn("configDigest", loader)
        self.assertIn("policyDigest", loader)
        self.assertIn("requestId", loader)
        self.assertIn("kindIdentity", loader)
        self.assertIn("SimpleStringLiteral", rule)
        self.assertIn("canonicalExpressionIdentity", rule)
        self.assertIn("evidence.matches", rule)
        self.assertIn("malformed or is not bound", rule)

    def test_adversarial_fixture_names_every_closed_gap(self) -> None:
        fixture = self.read("test/fixtures/adversarial_semantics.dart")
        for text in (
            "class WrappedColor extends Color",
            "LinearGradient",
            "BoxDecoration",
            "Border.all",
            "ColorFilter.mode",
            "CurvedAnimation",
            "Cubic(",
            "ColorTween",
            "AppWidgets.staticCard",
            "componentFactory(",
            "EdgeInsets.all(13)",
            "BorderRadius.circular(7)",
            "GuardianMissingSentinel",
        ):
            self.assertIn(text, fixture)


if __name__ == "__main__":
    unittest.main()
