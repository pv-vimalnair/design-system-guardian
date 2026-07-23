import 'package:analysis_server_plugin/plugin.dart';
import 'package:analysis_server_plugin/registry.dart';

import 'rules/color_rule.dart';
import 'rules/compilation_unit_attestation_rule.dart';
import 'rules/config_binding_rule.dart';
import 'rules/dimension_rule.dart';
import 'rules/effect_rule.dart';
import 'rules/icon_rule.dart';
import 'rules/motion_rule.dart';
import 'rules/radius_rule.dart';
import 'rules/sentinel_presence_rule.dart';
import 'rules/suppression_rule.dart';
import 'rules/text_style_rule.dart';
import 'rules/variant_rule.dart';
import 'rules/visual_primitive_rule.dart';
import 'rules/widget_rule.dart';

/// Registers strict, default-on warnings. Guardian intentionally does not
/// expose opt-in lint rules because incomplete enforcement cannot pass audit.
final class DesignSystemGuardianFlutterPlugin extends Plugin {
  @override
  String get name => 'Design System Guardian Flutter';

  @override
  void register(PluginRegistry registry) {
    registry.registerWarningRule(GuardianCompilationUnitAttestationRule());
    registry.registerWarningRule(GuardianConfigBindingRule());
    registry.registerWarningRule(GuardianColorRule());
    registry.registerWarningRule(GuardianTextStyleRule());
    registry.registerWarningRule(GuardianIconRule());
    registry.registerWarningRule(GuardianDimensionRule());
    registry.registerWarningRule(GuardianRadiusRule());
    registry.registerWarningRule(GuardianEffectRule());
    registry.registerWarningRule(GuardianMotionRule());
    registry.registerWarningRule(GuardianWidgetRule());
    registry.registerWarningRule(GuardianVariantRule());
    registry.registerWarningRule(GuardianVisualPrimitiveRule());
    registry.registerWarningRule(GuardianSentinelPresenceRule());
    registry.registerWarningRule(GuardianSuppressionRule());
  }
}
